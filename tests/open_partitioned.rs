//! Real forensic images are PARTITIONED. `Vfs::open` must recurse: detect the
//! MBR partition table, window into the NTFS partition, and mount it — not just
//! sniff a bare volume. Fixture: an MBR disk (type 0x07 @ LBA 2048) whose one
//! partition is the TSK-validated NTFS volume, acquired to E01.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, StreamId};
use forensic_vfs_engine::Vfs;

const PART_E01: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/partitioned_ntfs.E01"
);

#[test]
fn vfs_open_resolves_ntfs_partition_in_mbr_disk() {
    let vfs = Vfs::new();
    let evidence = vfs
        .open(Path::new(PART_E01))
        .expect("open partitioned disk");

    // The engine must descend MBR → partition 1 → NTFS.
    let fs = evidence.fs.expect("engine resolved the NTFS partition");
    assert_eq!(fs.kind(), forensic_vfs::FsKind::NTFS);

    let id = fs
        .lookup(fs.root(), b"file1.txt")
        .expect("lookup")
        .expect("file1.txt present");
    assert_eq!(id, FileId::NtfsRef { entry: 37, seq: 1 });

    let mut buf = [0u8; 512];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read");
    assert_eq!(n, 408);
    assert_eq!(&buf[..15], b"Just some bogus");
}
