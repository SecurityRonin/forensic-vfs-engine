//! Engine end-to-end: `Vfs::open` recognizes an AFF4 container (a Zip, so a
//! `Maybe` on the `PK\x03\x04` magic), decodes it via `aff4-core`, and mounts the
//! ext4 filesystem inside.
//!
//! Fixture: `ext4.aff4` wraps the TSK-validated `ext4.img` byte-for-byte as a
//! direct `aff4:ImageStream` (512-byte NullCompressor chunks, Deflate-stored in
//! the Zip). Oracle: the AFF4 reader reconstructs `ext4.img` byte-identically
//! (`virtual_disk_size` = 4,194,304), and The Sleuth Kit on that ext4 image
//! reports `hello.txt` = inode 13, 12 bytes, "Hello, ext4!".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, FsKind, StreamId};
use forensic_vfs_engine::Vfs;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ext4.aff4");

#[test]
fn vfs_open_decodes_aff4_to_its_ext4_payload() {
    let ev = Vfs::new()
        .open(Path::new(FIXTURE))
        .expect("open aff4 fixture");
    let fs = ev.fs.expect("AFF4 should decode to an ext4 filesystem");
    assert_eq!(fs.kind(), FsKind::EXT);

    let uri = ev.root.to_uri();
    assert!(
        uri.contains("container:aff4"),
        "locator should record the AFF4 container: {uri}"
    );

    let id = fs
        .lookup(fs.root(), b"hello.txt")
        .expect("lookup")
        .expect("hello.txt present");
    assert_eq!(id, FileId::ExtInode { ino: 13, gen: 0 });

    let mut buf = [0u8; 64];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read hello.txt through the engine");
    assert_eq!(&buf[..n], b"Hello, ext4!");
}

#[test]
fn aff4_decodes_to_the_oracle_virtual_disk_size() {
    // Decoder-level cross-check: the AFF4 reader's virtual disk equals ext4.img.
    let f = std::fs::File::open(FIXTURE).expect("open aff4 file");
    let reader = aff4::Aff4Reader::open_reader(Box::new(f)).expect("open aff4");
    assert_eq!(reader.virtual_disk_size(), 4 * 1024 * 1024);
}
