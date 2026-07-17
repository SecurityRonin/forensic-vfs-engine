//! Modern disks are GPT. `Vfs::open` must recognize the GPT header (past the
//! protective MBR), read its partition array, window into the NTFS partition,
//! and mount it. Fixture: a GPT disk (protective MBR + `EFI PART` + one Basic
//! Data partition = the TSK-validated NTFS volume @ LBA 2048), acquired to E01.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, StreamId};
use forensic_vfs_engine::Vfs;

const GPT_E01: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/gpt_ntfs.E01");

#[test]
fn vfs_open_resolves_ntfs_partition_in_gpt_disk() {
    let vfs = Vfs::new();
    let evidence = vfs.open(Path::new(GPT_E01)).expect("open gpt disk");

    let fs = evidence.fs.expect("engine resolved the GPT NTFS partition");
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
