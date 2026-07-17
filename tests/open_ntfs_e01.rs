//! The engine's reason to exist: ONE call opens real evidence. `Vfs::open` must
//! detect that `ntfs_sample.E01` is an EWF container holding an NTFS volume and
//! mount it as a `dyn FileSystem` — the Step-4 stack, now behind the engine.
//! Oracle: TSK (`file1.txt` = record 37, 408 bytes, "Just some bogus").

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, StreamId};
use forensic_vfs_engine::Vfs;

const E01: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ntfs_sample.E01");

#[test]
fn vfs_open_detects_and_mounts_ntfs_in_e01() {
    let vfs = Vfs::new();
    let evidence = vfs.open(Path::new(E01)).expect("open evidence");

    let fs = evidence.fs.expect("engine detected a filesystem");
    assert_eq!(fs.kind(), forensic_vfs::FsKind::NTFS);

    let id = fs
        .lookup(fs.root(), b"file1.txt")
        .expect("lookup")
        .expect("file1.txt present");
    assert_eq!(id, FileId::NtfsRef { entry: 37, seq: 1 });

    let mut buf = [0u8; 512];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read through the engine");
    assert_eq!(n, 408);
    assert_eq!(&buf[..15], b"Just some bogus");
}
