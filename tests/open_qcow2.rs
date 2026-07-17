//! QCOW2 is another single-stream container (magic `QFI\xfb`). Vfs::open decodes
//! it via qcow2-core and recurses into the NTFS inside. Fixture: a qcow2 of the
//! TSK-validated NTFS volume (qemu-img -O qcow2).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, StreamId};
use forensic_vfs_engine::Vfs;

const QCOW2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ntfs.qcow2");

#[test]
fn vfs_open_decodes_qcow2_container_to_ntfs() {
    let evidence = Vfs::new().open(Path::new(QCOW2)).expect("open qcow2");
    let fs = evidence
        .fs
        .expect("engine decoded the QCOW2 container to NTFS");
    assert_eq!(fs.kind(), forensic_vfs::FsKind::NTFS);
    let id = fs
        .lookup(fs.root(), b"file1.txt")
        .expect("lookup")
        .expect("file1.txt");
    assert_eq!(id, FileId::NtfsRef { entry: 37, seq: 1 });
    let mut buf = [0u8; 512];
    assert_eq!(fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap(), 408);
    assert_eq!(&buf[..15], b"Just some bogus");
}
