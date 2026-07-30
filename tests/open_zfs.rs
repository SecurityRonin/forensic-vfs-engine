//! `Vfs::open_source` detects a ZFS pool by its vdev-label nvlist config and
//! mounts it as a `dyn FileSystem` through `zfs_core::vfs::ZfsFs` — the ZFS leg
//! of the engine.
//!
//! ## Why the nvlist config, not the uberblock magic
//!
//! ZFS writes no fixed-offset filesystem magic. Its one structural marker is the
//! uberblock ring, which begins at byte `131072` of every vdev label — exactly
//! the resolver's `SNIFF_CAP` (128 KiB) boundary, so the head sniff window
//! `[0, 131072)` never carries an uberblock. The label's **XDR nvlist config**
//! does sit inside the window: it spans `[16384, 131072)` (`NVLIST_OFFSET`
//! `8 KiB + 8 KiB`, `NVLIST_SIZE` 112 KiB). The prober therefore parses that
//! config and requires the pool-identity keys every label carries
//! (`version` + `pool_guid` + `vdev_tree`), which is a structural check rather
//! than a byte-magic guess.
//!
//! ## Fixture (Tier-3 crafted, self-contained — no committed image)
//!
//! The image is assembled byte-by-byte from the ZFS on-disk structures the
//! reader parses, so the reader walks it end to end:
//!
//!   crafted vdev label   → XDR nvlist config @16384 (drives the probe)
//!                        → uberblock @131072, whose `rootbp` DVA[0] →
//!     MOS objset block
//!       meta-dnode → MOS dnode array
//!         obj 1  object directory  (micro-ZAP: `root_dataset` = 2)
//!         obj 2  DSL directory     (bonus `dd_head_dataset_obj` = 3)
//!         obj 3  DSL dataset       (bonus `ds_bp` → the ZPL objset block)
//!     ZPL objset block
//!       meta-dnode → ZPL dnode array
//!         obj 1  ZPL master node   (micro-ZAP: `ROOT` = 2, `SA_ATTRS` = 4)
//!         obj 2  root directory    (micro-ZAP: `hello.txt` = 3, `DT_REG`)
//!         obj 3  hello.txt         (SA bonus: mode + size; 12-byte file)
//!         obj 4  SA master, 5 REGISTRY, 6 LAYOUTS
//!
//! Every DVA offset is chosen by this builder, so the image is internally
//! coherent. ZFS checksums are verified **non-fatally** by `zfs-core`, so the
//! crafted blocks need no valid fletcher4. Ground truth is the *construction*:
//! what the builder writes is what the mount must return. The independent
//! correctness oracle for the ZFS reader itself is the env-gated real pool in
//! `zfs-forensic` (see that repo's `tests/data/README.md`); this test drives the
//! engine's dispatch arm, which is the thing under test here.
//!
//! The byte-layout helpers are the verified layout ported from `zfs-forensic`'s
//! own `core/tests/zpl_synth.rs` crafted-image test — the pure-Rust builder that
//! repo uses to exercise the `zpl_*` walk without shipping a 512 MiB pool.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use forensic_vfs::{DynSource, FileId, FsKind, ImageSource, StreamId, VfsResult};
use forensic_vfs_engine::{walk, Vfs};

/// Minimal in-memory `ImageSource` over an owned image buffer.
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

// ── ZFS on-disk constants the builder needs ──────────────────────────────────

/// `NVLIST_OFFSET` — `VDEV_PAD_SIZE` (8 KiB) + `VDEV_BOOT_HEADER_SIZE` (8 KiB).
const NVLIST_OFFSET: usize = 16 * 1024;
/// `UBERBLOCK_RING_OFFSET` — the ring begins 128 KiB into every label.
const UBERBLOCK_RING_OFFSET: usize = 128 * 1024;
/// The 4 MiB skew (two front labels + boot block) a DVA offset is added to.
const BOOT_SKEW: u64 = 0x0040_0000;
/// `UBERBLOCK_MAGIC` (`OuroBoros`).
const UBERBLOCK_MAGIC: u64 = 0x0000_0000_00ba_b10c;

const BLOCK: usize = 4096;
/// `dnode_phys_t` on-disk size.
const DNODE_SIZE: usize = 512;
/// `blkptr_t` on-disk size.
const BLKPTR_SIZE: usize = 128;

/// 8 MiB — large enough that the back labels (`L2`/`L3`, at `len - 512 KiB` and
/// `len - 256 KiB`) sit past every crafted block, so they stay all-zero and the
/// front `L0` uberblock is unambiguously the active one.
const IMAGE_LEN: usize = 8 * 1024 * 1024;

// ZPL dirent type bits live in the top 4 bits of a directory-entry value.
const DT_REG: u64 = 8 << 60;

// DMU bonus types.
const DMU_OT_SA: u8 = 44;
const DMU_OT_DSL_DIR: u8 = 12;
const DMU_OT_DSL_DATASET: u8 = 16;

/// The synthetic file's contents (object 3 in the ZPL).
const HELLO_CONTENT: &[u8] = b"hello, zfs!\n";

// ── XDR nvlist builder (the pool config that drives the prober) ──────────────

/// XDR-pad a byte length up to the next 4-byte boundary.
fn xdr_pad(len: usize) -> usize {
    len.div_ceil(4) * 4
}

/// Encode an XDR string: big-endian `i32` length then the bytes, zero-padded up
/// to a 4-byte boundary.
fn xdr_string(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut v = Vec::with_capacity(4 + xdr_pad(b.len()));
    v.extend_from_slice(&(b.len() as u32).to_be_bytes());
    v.extend_from_slice(b);
    v.resize(4 + xdr_pad(b.len()), 0);
    v
}

/// One nvpair value, in the subset the ZFS config uses.
enum Nv {
    U64(u64),
    Str(&'static str),
    List(Vec<(&'static str, Nv)>),
}

/// `DATA_TYPE_UINT64` / `DATA_TYPE_STRING` / `DATA_TYPE_NVLIST`.
fn nv_type(v: &Nv) -> u32 {
    match v {
        Nv::U64(_) => 8,
        Nv::Str(_) => 9,
        Nv::List(_) => 19,
    }
}

/// Encode an nvpair *value* (no name, no header).
fn nv_value_bytes(v: &Nv) -> Vec<u8> {
    match v {
        Nv::U64(n) => n.to_be_bytes().to_vec(),
        Nv::Str(s) => xdr_string(s),
        Nv::List(pairs) => nv_body(pairs),
    }
}

/// Encode an nvlist *body*: `nvl_version` + `nvl_nvflag`, the nvpairs, and the
/// zero terminator. Each nvpair's `encoded_size` counts the whole pair from its
/// own `encoded_size` field — that is what the parser advances by.
fn nv_body(pairs: &[(&'static str, Nv)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_be_bytes()); // nvl_version
    out.extend_from_slice(&1u32.to_be_bytes()); // nvl_nvflag
    for (name, value) in pairs {
        let name_b = xdr_string(name);
        let val_b = nv_value_bytes(value);
        // encoded_size(4) + decoded_size(4) + name + data_type(4) + nelem(4) + value
        let encoded = 8 + name_b.len() + 8 + val_b.len();
        out.extend_from_slice(&(encoded as u32).to_be_bytes()); // encoded_size
        out.extend_from_slice(&(encoded as u32).to_be_bytes()); // decoded_size
        out.extend_from_slice(&name_b);
        out.extend_from_slice(&nv_type(value).to_be_bytes()); // data_type
        out.extend_from_slice(&1u32.to_be_bytes()); // nelem
        out.extend_from_slice(&val_b);
    }
    out.extend_from_slice(&0u32.to_be_bytes()); // terminator encoded_size
    out.extend_from_slice(&0u32.to_be_bytes()); // terminator decoded_size
    out
}

/// The packed label config: the 4-byte header (`NV_ENCODE_XDR`, endian, 2 rsvd)
/// then the XDR body carrying the pool-identity keys the prober requires.
fn label_config() -> Vec<u8> {
    let mut v = vec![1u8, 1, 0, 0];
    v.extend_from_slice(&nv_body(&[
        ("version", Nv::U64(5000)),
        ("name", Nv::Str("tank")),
        ("state", Nv::U64(0)),
        ("txg", Nv::U64(42)),
        ("pool_guid", Nv::U64(0x1234_5678_9abc_def0)),
        (
            "vdev_tree",
            Nv::List(vec![
                ("type", Nv::Str("disk")),
                ("ashift", Nv::U64(9)),
                ("asize", Nv::U64(IMAGE_LEN as u64)),
            ]),
        ),
    ]));
    v
}

// ── ZFS structure builders (ported from zfs-forensic's zpl_synth.rs) ─────────

/// A 512-byte micro-ZAP block: header `ZBT_MICRO` then 64-byte entries
/// (value @0 little-endian, NUL-terminated name @14).
fn micro_zap(entries: &[(&str, u64)]) -> Vec<u8> {
    const ZBT_MICRO: u64 = (1 << 63) | 3;
    let mut b = vec![0u8; 512];
    b[0..8].copy_from_slice(&ZBT_MICRO.to_le_bytes());
    for (i, (name, val)) in entries.iter().enumerate() {
        let off = 64 + i * 64;
        b[off..off + 8].copy_from_slice(&val.to_le_bytes());
        let nb = name.as_bytes();
        b[off + 14..off + 14 + nb.len()].copy_from_slice(nb);
    }
    b
}

/// Write a little-endian `blkptr_t` at `off` pointing one L0 data block at
/// vdev-relative byte `phys`, of logical/physical size `size`, uncompressed.
fn write_blkptr(buf: &mut [u8], off: usize, phys: u64, size: usize) {
    if phys == 0 {
        return; // an all-zero (hole) blkptr: the payload lives in the bonus
    }
    let offset_sectors = (phys - BOOT_SKEW) >> 9;
    let asize_sectors = (size as u64).div_ceil(512);
    let w0 = asize_sectors & 0x00ff_ffff; // vdev 0
    let w1 = offset_sectors & 0x7fff_ffff_ffff_ffff;
    buf[off..off + 8].copy_from_slice(&w0.to_le_bytes());
    buf[off + 8..off + 16].copy_from_slice(&w1.to_le_bytes());
    // blk_prop @48: LSIZE(0-15) + PSIZE(16-31) + comp(32-38) + byteorder(63),
    // sizes stored as sectors-1.
    let sectors = (size as u64).div_ceil(512);
    let lsize_raw = sectors - 1;
    let comp: u64 = 2; // ZIO_COMPRESS_OFF
    let byteorder: u64 = 1; // little-endian
    let prop =
        (lsize_raw & 0xffff) | ((lsize_raw & 0xffff) << 16) | (comp << 32) | (byteorder << 63);
    buf[off + 48..off + 56].copy_from_slice(&prop.to_le_bytes());
}

/// A 512-byte `dnode_phys_t` whose single L0 data block is `phys`.
fn dnode(phys: u64, bonustype: u8, bonus: &[u8]) -> [u8; DNODE_SIZE] {
    let mut d = [0u8; DNODE_SIZE];
    d[0] = 10; // dn_type = DMU_OT_DNODE (non-zero: a live slot)
    d[1] = 12; // dn_indblkshift (4 KiB indirect)
    d[2] = 1; // dn_nlevels = 1
    d[3] = 1; // dn_nblkptr = 1
    d[4] = bonustype;
    d[8..10].copy_from_slice(&((BLOCK as u16) >> 9).to_le_bytes()); // dn_datablkszsec
    d[10..12].copy_from_slice(&(bonus.len() as u16).to_le_bytes()); // dn_bonuslen
    d[16..24].copy_from_slice(&0u64.to_le_bytes()); // dn_maxblkid = 0
    write_blkptr(&mut d, 64, phys, BLOCK);
    let bonus_off = 64 + BLKPTR_SIZE;
    d[bonus_off..bonus_off + bonus.len()].copy_from_slice(bonus);
    d
}

/// A dnode whose data block is a micro-ZAP (bonus empty).
fn zap_dnode(phys: u64) -> [u8; DNODE_SIZE] {
    dnode(phys, 0, &[])
}

/// A `BLOCK`-byte objset block whose meta-dnode points at the object dnode array
/// at `dnode_array_phys`; `os_type` @704 = `DMU_OST_ZFS` (2).
fn objset_block(dnode_array_phys: u64, dnodes: usize) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK];
    b[0] = 10;
    b[1] = 12;
    b[2] = 1;
    b[3] = 1;
    let arr_bytes = dnodes * DNODE_SIZE;
    let dblk_sectors = arr_bytes.div_ceil(512) as u16;
    b[8..10].copy_from_slice(&dblk_sectors.to_le_bytes());
    b[16..24].copy_from_slice(&0u64.to_le_bytes()); // maxblkid = 0
    write_blkptr(&mut b, 64, dnode_array_phys, arr_bytes.max(512));
    b[704..712].copy_from_slice(&2u64.to_le_bytes()); // os_type = DMU_OST_ZFS
    b
}

/// A `dsl_dir_phys_t` bonus: `dd_head_dataset_obj` @8.
fn dsl_dir_bonus(head_dataset_obj: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256];
    v[8..16].copy_from_slice(&head_dataset_obj.to_le_bytes());
    v
}

/// A `dsl_dataset_phys_t` bonus: the 128-byte `ds_bp` @128 → the ZPL objset.
fn dsl_dataset_bonus(zpl_objset_phys: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256];
    write_blkptr(&mut v, 128, zpl_objset_phys, BLOCK);
    v
}

// SA attribute ids used by the crafted registry/layout below.
const SA_MAGIC: u32 = 0x2F_505A;
const ID_ZPL_MODE: u16 = 5;
const ID_ZPL_SIZE: u16 = 6;

/// A `DMU_OT_SA` bonus for layout 1 (`[ZPL_MODE(8), ZPL_SIZE(8)]`).
fn sa_bonus(mode: u64, size: u64) -> Vec<u8> {
    let mut v = vec![0u8; 8 + 16];
    v[0..4].copy_from_slice(&SA_MAGIC.to_le_bytes());
    let info: u16 = 1 | (1 << 10); // layout_num = 1, hdrsz = 8 bytes
    v[4..6].copy_from_slice(&info.to_le_bytes());
    v[8..16].copy_from_slice(&mode.to_le_bytes());
    v[16..24].copy_from_slice(&size.to_le_bytes());
    v
}

/// Pack a micro-ZAP `LAYOUTS` value so the ids read back as big-endian u16s.
fn layout_value(ids: &[u16]) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, &id) in ids.iter().enumerate().take(4) {
        bytes[i * 2..i * 2 + 2].copy_from_slice(&id.to_be_bytes());
    }
    u64::from_le_bytes(bytes)
}

/// Pack an SA `REGISTRY` value: length in bits[24..40), id in bits[0..16).
fn registry_value(id: u16, size: u16) -> u64 {
    (u64::from(size) << 24) | u64::from(id)
}

/// A 1 KiB uberblock slot whose `rootbp` points at the MOS objset block.
fn uberblock(mos_phys: u64) -> Vec<u8> {
    let mut ub = vec![0u8; 1024];
    ub[0..8].copy_from_slice(&UBERBLOCK_MAGIC.to_le_bytes()); // ub_magic
    ub[8..16].copy_from_slice(&5000u64.to_le_bytes()); // ub_version
    ub[16..24].copy_from_slice(&42u64.to_le_bytes()); // ub_txg
    ub[24..32].copy_from_slice(&0xdead_beefu64.to_le_bytes()); // ub_guid_sum
    ub[32..40].copy_from_slice(&1_700_000_000u64.to_le_bytes()); // ub_timestamp
    write_blkptr(&mut ub, 40, mos_phys, BLOCK); // ub_rootbp → MOS objset
    ub
}

/// Assemble the complete walkable ZFS mini-image.
fn walkable_image() -> Vec<u8> {
    // Every crafted block sits at or past the 4 MiB boot skew, so a DVA can
    // address it, and well before the back labels.
    let base = BOOT_SKEW as usize;
    let mos_phys = base as u64;
    let mos_dnode_arr_phys = (base + BLOCK) as u64;
    let obj_dir_phys = (base + 2 * BLOCK) as u64;
    let zpl_objset_phys = (base + 3 * BLOCK) as u64;
    let zpl_dnode_arr_phys = (base + 4 * BLOCK) as u64;
    let zpl_master_phys = (base + 5 * BLOCK) as u64;
    let zpl_root_phys = (base + 6 * BLOCK) as u64;
    let zpl_file_phys = (base + 7 * BLOCK) as u64;
    let sa_master_phys = (base + 8 * BLOCK) as u64;
    let sa_registry_phys = (base + 9 * BLOCK) as u64;
    let sa_layouts_phys = (base + 10 * BLOCK) as u64;

    let mut img = vec![0u8; IMAGE_LEN];

    // --- the crafted vdev label: nvlist config + uberblock ring ---
    let cfg = label_config();
    img[NVLIST_OFFSET..NVLIST_OFFSET + cfg.len()].copy_from_slice(&cfg);
    let ub = uberblock(mos_phys);
    img[UBERBLOCK_RING_OFFSET..UBERBLOCK_RING_OFFSET + ub.len()].copy_from_slice(&ub);

    // --- MOS objset block (at the rootbp DVA) ---
    let mos_objset = objset_block(mos_dnode_arr_phys, 4);
    img[mos_phys as usize..mos_phys as usize + mos_objset.len()].copy_from_slice(&mos_objset);

    // --- MOS dnode array: objects 0..=3 ---
    let mut mos_arr = vec![0u8; 4 * DNODE_SIZE];
    mos_arr[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&zap_dnode(obj_dir_phys));
    mos_arr[2 * DNODE_SIZE..3 * DNODE_SIZE].copy_from_slice(&dnode(
        0,
        DMU_OT_DSL_DIR,
        &dsl_dir_bonus(3),
    ));
    mos_arr[3 * DNODE_SIZE..4 * DNODE_SIZE].copy_from_slice(&dnode(
        0,
        DMU_OT_DSL_DATASET,
        &dsl_dataset_bonus(zpl_objset_phys),
    ));
    let mos_arr_off = mos_dnode_arr_phys as usize;
    img[mos_arr_off..mos_arr_off + mos_arr.len()].copy_from_slice(&mos_arr);

    // --- object directory micro-ZAP (obj 1's data block) ---
    let obj_dir = micro_zap(&[("root_dataset", 2)]);
    let obj_dir_off = obj_dir_phys as usize;
    img[obj_dir_off..obj_dir_off + obj_dir.len()].copy_from_slice(&obj_dir);

    // --- ZPL objset block ---
    let zpl_objset = objset_block(zpl_dnode_arr_phys, 7);
    let zpl_objset_off = zpl_objset_phys as usize;
    img[zpl_objset_off..zpl_objset_off + zpl_objset.len()].copy_from_slice(&zpl_objset);

    // --- ZPL dnode array: objects 0..=6 ---
    let mut zpl_arr = vec![0u8; 7 * DNODE_SIZE];
    zpl_arr[DNODE_SIZE..2 * DNODE_SIZE].copy_from_slice(&zap_dnode(zpl_master_phys));
    zpl_arr[2 * DNODE_SIZE..3 * DNODE_SIZE].copy_from_slice(&zap_dnode(zpl_root_phys));
    zpl_arr[3 * DNODE_SIZE..4 * DNODE_SIZE].copy_from_slice(&dnode(
        zpl_file_phys,
        DMU_OT_SA,
        &sa_bonus(0o100_644, HELLO_CONTENT.len() as u64),
    ));
    zpl_arr[4 * DNODE_SIZE..5 * DNODE_SIZE].copy_from_slice(&zap_dnode(sa_master_phys));
    zpl_arr[5 * DNODE_SIZE..6 * DNODE_SIZE].copy_from_slice(&zap_dnode(sa_registry_phys));
    zpl_arr[6 * DNODE_SIZE..7 * DNODE_SIZE].copy_from_slice(&zap_dnode(sa_layouts_phys));
    let zpl_arr_off = zpl_dnode_arr_phys as usize;
    img[zpl_arr_off..zpl_arr_off + zpl_arr.len()].copy_from_slice(&zpl_arr);

    // --- ZPL master node micro-ZAP: ROOT = 2, VERSION = 5, SA_ATTRS = 4 ---
    let master = micro_zap(&[("ROOT", 2), ("VERSION", 5), ("SA_ATTRS", 4)]);
    let master_off = zpl_master_phys as usize;
    img[master_off..master_off + master.len()].copy_from_slice(&master);

    // --- ZPL root directory micro-ZAP: hello.txt = obj 3 (DT_REG) ---
    let root = micro_zap(&[("hello.txt", 0x3 | DT_REG)]);
    let root_off = zpl_root_phys as usize;
    img[root_off..root_off + root.len()].copy_from_slice(&root);

    // --- SA master / REGISTRY / LAYOUTS micro-ZAPs ---
    let sa_master = micro_zap(&[("REGISTRY", 5), ("LAYOUTS", 6)]);
    let sa_master_off = sa_master_phys as usize;
    img[sa_master_off..sa_master_off + sa_master.len()].copy_from_slice(&sa_master);

    let sa_registry = micro_zap(&[
        ("ZPL_MODE", registry_value(ID_ZPL_MODE, 8)),
        ("ZPL_SIZE", registry_value(ID_ZPL_SIZE, 8)),
    ]);
    let sa_registry_off = sa_registry_phys as usize;
    img[sa_registry_off..sa_registry_off + sa_registry.len()].copy_from_slice(&sa_registry);

    let sa_layouts = micro_zap(&[("1", layout_value(&[ID_ZPL_MODE, ID_ZPL_SIZE]))]);
    let sa_layouts_off = sa_layouts_phys as usize;
    img[sa_layouts_off..sa_layouts_off + sa_layouts.len()].copy_from_slice(&sa_layouts);

    // --- hello.txt's data block ---
    let file_off = zpl_file_phys as usize;
    img[file_off..file_off + HELLO_CONTENT.len()].copy_from_slice(HELLO_CONTENT);

    img
}

#[test]
fn vfs_detects_and_mounts_zfs_from_the_label_nvlist_config() {
    let src: DynSource = Arc::new(Mem(walkable_image()));
    let fs = Vfs::new()
        .open_source(src)
        .expect("resolve")
        .expect("engine detected zfs from the vdev-label nvlist config");
    assert_eq!(fs.kind(), FsKind::ZFS);

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk zfs")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "hello.txt"),
        "walk should surface the crafted root file hello.txt: {names:?}"
    );
}

/// The mounted filesystem reads a file's bytes through the generic
/// `FileSystem::read_at` contract — the engine's consumers never touch
/// `zfs_core`'s own `zpl_*` API.
#[test]
fn mounted_zfs_reads_file_content_through_the_vfs_contract() {
    let src: DynSource = Arc::new(Mem(walkable_image()));
    let fs = Vfs::new()
        .open_source(src)
        .expect("resolve")
        .expect("engine detected zfs");

    let root = fs.root();
    let id = fs
        .lookup(root, b"hello.txt")
        .expect("lookup hello.txt")
        .expect("hello.txt is present in the crafted root directory");

    let meta = fs.meta(id).expect("meta for hello.txt");
    assert_eq!(meta.size, HELLO_CONTENT.len() as u64);

    let mut buf = vec![0u8; HELLO_CONTENT.len()];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read hello.txt");
    assert_eq!(&buf[..n], HELLO_CONTENT);
}

/// The ZFS prober is registered in `default_openers`, so a consumer that builds
/// the default registry reaches ZFS without naming it.
#[test]
fn default_openers_registers_the_zfs_prober() {
    let kinds: Vec<FsKind> = forensic_vfs_engine::default_openers()
        .filesystems()
        .iter()
        .map(|p| p.kind())
        .collect();
    assert!(
        kinds.contains(&FsKind::ZFS),
        "zfs prober registered: {kinds:?}"
    );
}

/// A source with no ZFS label resolves to "no filesystem", never a false ZFS
/// mount — the prober declines rather than guessing.
#[test]
fn a_non_zfs_source_is_not_claimed_as_zfs() {
    let src: DynSource = Arc::new(Mem(vec![0u8; IMAGE_LEN]));
    let resolved = Vfs::new()
        .open_source(src)
        .expect("resolve an all-zero image");
    assert!(
        resolved.is_none(),
        "an all-zero image is not a ZFS pool (or any filesystem)"
    );
}

/// `FileId` round-trips through the ZFS adapter: the root is an opaque ZFS
/// object id, so a consumer can persist and replay it.
#[test]
fn zfs_root_file_id_is_an_opaque_object_id() {
    let src: DynSource = Arc::new(Mem(walkable_image()));
    let fs = Vfs::new()
        .open_source(src)
        .expect("resolve")
        .expect("engine detected zfs");
    assert!(
        matches!(fs.root(), FileId::Opaque(_)),
        "ZFS addresses objects by object id"
    );
}
