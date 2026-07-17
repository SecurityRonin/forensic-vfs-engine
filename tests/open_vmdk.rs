//! VMDK (VMware) monolithic-sparse container (magic `KDMV`). Vfs::open decodes
//! it via vmdk-core and recurses into the NTFS inside. Fixture: a
//! monolithicSparse VMDK of the TSK-validated NTFS volume (qemu-img -O vmdk).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, StreamId};
use forensic_vfs_engine::Vfs;

const VMDK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ntfs.vmdk");

#[test]
fn vfs_open_decodes_vmdk_container_to_ntfs() {
    let evidence = Vfs::new().open(Path::new(VMDK)).expect("open vmdk");
    let fs = evidence
        .fs
        .expect("engine decoded the VMDK container to NTFS");
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
