//! `Vfs::open` detects a bare ext4 volume (no partition table) by its superblock
//! magic and mounts it as a `dyn FileSystem` — the ext4 leg of the engine.
//! Oracle: The Sleuth Kit on the same image (`fls`/`istat`/`icat`):
//! `hello.txt` = inode 13, 12 bytes, "Hello, ext4!".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, FsKind, StreamId};
use forensic_vfs_engine::Vfs;

const IMG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ext4.img");

#[test]
fn vfs_open_detects_and_mounts_bare_ext4() {
    let vfs = Vfs::new();
    let evidence = vfs.open(Path::new(IMG)).expect("open evidence");

    let fs = evidence.fs.expect("engine detected a filesystem");
    assert_eq!(fs.kind(), FsKind::EXT);

    let id = fs
        .lookup(fs.root(), b"hello.txt")
        .expect("lookup")
        .expect("hello.txt present");
    assert_eq!(id, FileId::ExtInode { ino: 13, gen: 0 });

    let mut buf = [0u8; 64];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read through the engine");
    assert_eq!(&buf[..n], b"Hello, ext4!");
}
