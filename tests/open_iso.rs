//! `Vfs::open` detects a plain ISO 9660 volume by its Primary Volume Descriptor
//! (`CD001` at byte offset 32769, LBA 16) and mounts it as a `dyn FileSystem` —
//! the ISO 9660 leg of the engine. This requires the resolver's sniff window to
//! reach past 32768; the earlier 4096-byte head could not see the PVD.
//!
//! Oracle: The Sleuth Kit on the same image (`fls`/`istat`/`icat -f iso9660`):
//! root directory at block 23; `HELLO.TXT;1` = extent LBA 24, 15 bytes,
//! "Hello, iso9660!".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, FsKind, StreamId};
use forensic_vfs_engine::Vfs;

const IMG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/test.iso");

#[test]
fn vfs_open_detects_and_mounts_iso9660() {
    let vfs = Vfs::new();
    let evidence = vfs.open(Path::new(IMG)).expect("open evidence");

    let fs = evidence.fs.expect("engine detected a filesystem");
    assert_eq!(fs.kind(), FsKind::ISO9660);
    assert_eq!(fs.root(), FileId::IsoExtent { block: 23 });

    let id = fs
        .lookup(fs.root(), b"hello.txt")
        .expect("lookup")
        .expect("hello.txt present");
    assert_eq!(id, FileId::IsoExtent { block: 24 });

    let mut buf = [0u8; 64];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read through the engine");
    assert_eq!(&buf[..n], b"Hello, iso9660!");
}
