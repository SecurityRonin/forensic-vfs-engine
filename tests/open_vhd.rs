//! A VHD is a single-stream container that fits the ContainerDecoder model.
//! Vfs::open must detect the `conectix` footer, decode the VHD to its virtual
//! disk (a dyn ImageSource), and recurse into the NTFS volume inside. Fixture:
//! a dynamic VHD of the TSK-validated NTFS volume (qemu-img -O vpc).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, StreamId};
use forensic_vfs_engine::Vfs;

const VHD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ntfs.vhd");

#[test]
fn vfs_open_decodes_vhd_container_to_ntfs() {
    let evidence = Vfs::new().open(Path::new(VHD)).expect("open vhd");
    let fs = evidence
        .fs
        .expect("engine decoded the VHD container to NTFS");
    assert_eq!(fs.kind(), forensic_vfs::FsKind::NTFS);

    let id = fs
        .lookup(fs.root(), b"file1.txt")
        .expect("lookup")
        .expect("file1.txt present");
    assert_eq!(id, FileId::NtfsRef { entry: 37, seq: 1 });
    let mut buf = [0u8; 512];
    assert_eq!(fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap(), 408);
    assert_eq!(&buf[..15], b"Just some bogus");
}
