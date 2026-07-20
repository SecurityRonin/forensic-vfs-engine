//! `Vfs::open_source` detects a btrfs volume by its `_BHRfS_M` superblock magic
//! (byte 0x10040, within the resolver's 128 KiB head window) and mounts it as a
//! `dyn FileSystem` through `btrfs_core::vfs::BtrfsFs` — the btrfs leg of the
//! engine.
//!
//! Fixture: a synthetic, walkable btrfs image assembled in-memory (no `mkfs`).
//! The byte layout — an identity `sys_chunk_array`, a ROOT_TREE leaf holding the
//! FS_TREE ROOT_ITEM, and an FS_TREE leaf with a directory + an inline file — is
//! the verified layout ported from `btrfs-forensic`'s own `core/src/vfs.rs`
//! crafted-image test (`walkable_image`), the pure-Rust builder that repo uses to
//! exercise `BtrfsFs::open` without shipping a 256 MiB volume. The engine only
//! calls `BtrfsFs::open`, so the same crafted image drives its dispatch arm.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use forensic_vfs::{DynSource, FsKind, ImageSource, VfsResult};
use forensic_vfs_engine::{walk, Vfs};

/// Minimal in-memory ImageSource over an owned image buffer.
struct Mem(Vec<u8>);
impl ImageSource for Mem {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let start = (offset as usize).min(self.0.len());
        let avail = &self.0[start..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
}

const NODESIZE: usize = 16_384;
const HDR_END: usize = 101;
const ITEM_STRIDE: usize = 25;
const SUPER_OFFSET: usize = 65_536;
const SUPER_SIZE: usize = 4096;
const ROOT_LOGICAL: u64 = 0x20_000;
const FS_LEAF_LOGICAL: u64 = 0x30_000;
const CHUNK_LEN: u64 = 4 * 1024 * 1024;
const IMAGE_LEN: usize = FS_LEAF_LOGICAL as usize + NODESIZE;

fn crc32c(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Build a leaf node (`owner`, level 0) with `items = (objectid, type, key_off,
/// data)` laid out backward from the node end, and a fixed-up crc32c.
fn build_leaf(owner: u64, items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&30_654_464u64.to_le_bytes()); // bytenr
    node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
    node[0x60..0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
    node[0x64] = 0; // leaf
    let mut tail = NODESIZE;
    for (i, (oid, ty, koff, data)) in items.iter().enumerate() {
        let io = HDR_END + i * ITEM_STRIDE;
        node[io..io + 8].copy_from_slice(&oid.to_le_bytes());
        node[io + 8] = *ty;
        node[io + 9..io + 17].copy_from_slice(&koff.to_le_bytes());
        tail -= data.len();
        let doff = (tail - HDR_END) as u32;
        node[io + 17..io + 21].copy_from_slice(&doff.to_le_bytes());
        node[io + 21..io + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
        node[tail..tail + data.len()].copy_from_slice(data);
    }
    let c = crc32c(&node[0x20..]);
    node[0..4].copy_from_slice(&c.to_le_bytes());
    node
}

/// A 160-byte INODE_ITEM: size@16, nlink@40, uid@44, gid@48, mode@52, timestamps.
fn inode_item(size: u64, mode: u32, nlink: u32, uid: u32, gid: u32, otime_sec: u64) -> Vec<u8> {
    let mut d = vec![0u8; 160];
    d[16..24].copy_from_slice(&size.to_le_bytes());
    d[40..44].copy_from_slice(&nlink.to_le_bytes());
    d[44..48].copy_from_slice(&uid.to_le_bytes());
    d[48..52].copy_from_slice(&gid.to_le_bytes());
    d[52..56].copy_from_slice(&mode.to_le_bytes());
    d[112..120].copy_from_slice(&111u64.to_le_bytes()); // atime.sec
    d[124..132].copy_from_slice(&222u64.to_le_bytes()); // ctime.sec
    d[136..144].copy_from_slice(&333u64.to_le_bytes()); // mtime.sec
    d[148..156].copy_from_slice(&otime_sec.to_le_bytes()); // otime.sec
    d
}

/// An inline EXTENT_DATA (type 0) carrying `payload` (ram_bytes = len).
fn inline_extent(payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 21 + payload.len()];
    d[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    d[20] = 0; // inline
    d[21..].copy_from_slice(payload);
    d
}

/// A DIR_ITEM body: location key[17] + transid(8) + data_len(2) + name_len(2) +
/// type(1) + name.
fn dir_item(child: u64, ft: u8, name: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 30 + name.len()];
    d[0..8].copy_from_slice(&child.to_le_bytes());
    d[8] = 1; // location.type = INODE_ITEM
    d[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes());
    d[29] = ft;
    d[30..].copy_from_slice(name);
    d
}

/// A CHUNK_TREE leaf identity-mapping `[0, CHUNK_LEN)`.
fn build_chunk_leaf() -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&0u64.to_le_bytes()); // bytenr
    node[0x58..0x60].copy_from_slice(&3u64.to_le_bytes()); // owner = CHUNK_TREE
    node[0x60..0x64].copy_from_slice(&1u32.to_le_bytes()); // nritems
    node[0x64] = 0; // leaf
    let mut chunk = vec![0u8; 48 + 32];
    chunk[0..8].copy_from_slice(&CHUNK_LEN.to_le_bytes()); // length
    chunk[24..32].copy_from_slice(&0x1u64.to_le_bytes()); // type DATA
    chunk[44..46].copy_from_slice(&1u16.to_le_bytes()); // num_stripes
    chunk[46..48].copy_from_slice(&1u16.to_le_bytes()); // sub_stripes
    chunk[48..56].copy_from_slice(&1u64.to_le_bytes()); // stripe devid
    chunk[56..64].copy_from_slice(&0u64.to_le_bytes()); // stripe offset (identity)
    let data_tail = NODESIZE - chunk.len();
    let io = HDR_END;
    node[io..io + 8].copy_from_slice(&256u64.to_le_bytes()); // FIRST_CHUNK_TREE
    node[io + 8] = 228; // CHUNK_ITEM
    node[io + 9..io + 17].copy_from_slice(&0u64.to_le_bytes()); // logical 0
    node[io + 17..io + 21].copy_from_slice(&((data_tail - HDR_END) as u32).to_le_bytes());
    node[io + 21..io + 25].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    node[data_tail..data_tail + chunk.len()].copy_from_slice(&chunk);
    let c = crc32c(&node[0x20..]);
    node[0..4].copy_from_slice(&c.to_le_bytes());
    node
}

/// A superblock whose `root` = ROOT_LOGICAL, `chunk_root` = 0, sys_chunk_array
/// identity-maps `[0, CHUNK_LEN)`.
fn build_super() -> Vec<u8> {
    let mut sb = vec![0u8; SUPER_SIZE];
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    sb[0x30..0x38].copy_from_slice(&65536u64.to_le_bytes()); // bytenr
    sb[0x50..0x58].copy_from_slice(&ROOT_LOGICAL.to_le_bytes()); // root
    sb[0x58..0x60].copy_from_slice(&0u64.to_le_bytes()); // chunk_root logical 0
    sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
    sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes()); // nodesize
    let arr = 0x32busize;
    sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes());
    sb[arr + 8] = 228;
    sb[arr + 9..arr + 17].copy_from_slice(&0u64.to_le_bytes()); // logical 0
    let mut ci = vec![0u8; 48 + 32];
    ci[0..8].copy_from_slice(&CHUNK_LEN.to_le_bytes());
    ci[24..32].copy_from_slice(&0x2u64.to_le_bytes()); // SYSTEM
    ci[44..46].copy_from_slice(&1u16.to_le_bytes());
    ci[46..48].copy_from_slice(&1u16.to_le_bytes());
    ci[48..56].copy_from_slice(&1u64.to_le_bytes());
    ci[56..64].copy_from_slice(&0u64.to_le_bytes());
    sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
    sb[0xa0..0xa4].copy_from_slice(&((17 + ci.len()) as u32).to_le_bytes());
    sb
}

/// Assemble a walkable in-memory btrfs image: chunk leaf @0, superblock @0x10000,
/// ROOT_TREE leaf @ROOT_LOGICAL, FS_TREE leaf @FS_LEAF_LOGICAL. The FS_TREE root
/// dir (256) holds `note.txt` (257, an inline-extent file).
fn walkable_image() -> Vec<u8> {
    let mut img = vec![0u8; IMAGE_LEN];
    img[0..NODESIZE].copy_from_slice(&build_chunk_leaf());
    img[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE].copy_from_slice(&build_super());

    // ROOT_TREE leaf: FS_TREE (objectid 5) ROOT_ITEM whose bytenr@176 =
    // FS_LEAF_LOGICAL, root_dirid@168 = 256, level@238 = 0.
    let mut root_item = vec![0u8; 239];
    root_item[168..176].copy_from_slice(&256u64.to_le_bytes()); // root_dirid
    root_item[176..184].copy_from_slice(&FS_LEAF_LOGICAL.to_le_bytes()); // bytenr
    let root_leaf = build_leaf(
        1, /* ROOT_TREE */
        &[(5, 132 /* ROOT_ITEM */, 0, root_item)],
    );
    img[ROOT_LOGICAL as usize..ROOT_LOGICAL as usize + NODESIZE].copy_from_slice(&root_leaf);

    // FS_TREE leaf: root dir 256 with note.txt (257, inline content).
    let fs_leaf = build_leaf(
        5, /* FS_TREE */
        &[
            (256, 1, 0, inode_item(0, 0o040_755, 2, 0, 0, 500)),
            (256, 84, 10, dir_item(257, 1 /* FT_REG */, b"note.txt")),
            (257, 1, 0, inode_item(9, 0o100_644, 1, 1000, 1000, 700)),
            (257, 108, 0, inline_extent(b"note body")),
        ],
    );
    img[FS_LEAF_LOGICAL as usize..FS_LEAF_LOGICAL as usize + fs_leaf.len()]
        .copy_from_slice(&fs_leaf);
    img
}

#[test]
fn vfs_detects_and_mounts_btrfs_from_the_superblock() {
    let src: DynSource = Arc::new(Mem(walkable_image()));
    let fs = Vfs::new()
        .open_source(src)
        .expect("resolve")
        .expect("engine detected btrfs from the _BHRfS_M superblock magic");
    assert_eq!(fs.kind(), FsKind::BTRFS);

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk btrfs")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "note.txt"),
        "walk should surface the crafted root file note.txt: {names:?}"
    );
}
