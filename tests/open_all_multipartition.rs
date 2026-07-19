//! `Vfs::open` mounts only the FIRST filesystem a partitioned disk carries; a
//! real multi-partition disk (a Windows GPT layout is the canonical case: a tiny
//! FAT EFI System Partition in slot 0 shadowing the NTFS Windows volume) needs
//! EVERY partition surfaced. `Vfs::open_all` forks on the top-level volume system
//! and resolves each volume independently, returning one `Evidence` per partition
//! that mounts a filesystem.
//!
//! Fixture: a synthetic MBR disk assembled at runtime from two committed,
//! independently TSK-validated bare volumes — `ntfs_volume.bin` (the
//! `SampleTinyNtfsVolume`; `file1.txt` = MFT record 37, 408 bytes, "Just some
//! bogus") in partition 0 and `fat.img` (root holds `HELLO.TXT`) in partition 1.
//! Proving BOTH mount is the point: the NTFS volume that `open` would skip is now
//! reachable.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::{FileId, FsKind, StreamId};
use forensic_vfs_engine::Vfs;

const NTFS_VOL: &[u8] = include_bytes!("data/ntfs_volume.bin");
const FAT_VOL: &[u8] = include_bytes!("data/fat.img");

const SECTOR: usize = 512;

fn put_u32_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Round a byte length up to a whole number of 512-byte sectors.
fn sectors(len: usize) -> u32 {
    u32::try_from(len.div_ceil(SECTOR)).unwrap()
}

/// Assemble a two-partition MBR disk: sector 0 is the partition table, then the
/// NTFS volume (partition 0, type 0x07) followed by the FAT volume (partition 1,
/// type 0x0c). Returns the whole disk image bytes.
fn build_mbr_disk(ntfs: &[u8], fat: &[u8]) -> Vec<u8> {
    let ntfs_sectors = sectors(ntfs.len());
    let fat_sectors = sectors(fat.len());
    let ntfs_start_lba: u32 = 1;
    let fat_start_lba: u32 = ntfs_start_lba + ntfs_sectors;

    let mut disk = vec![0u8; SECTOR];
    // Partition 0 (NTFS): entry at 446, type 0x07.
    disk[446] = 0x00; // not bootable
    disk[446 + 4] = 0x07; // NTFS/HPFS/exFAT
    put_u32_le(&mut disk, 446 + 8, ntfs_start_lba);
    put_u32_le(&mut disk, 446 + 12, ntfs_sectors);
    // Partition 1 (FAT): entry at 462, type 0x0c (FAT32 LBA).
    disk[462 + 4] = 0x0c;
    put_u32_le(&mut disk, 462 + 8, fat_start_lba);
    put_u32_le(&mut disk, 462 + 12, fat_sectors);
    // Boot signature.
    disk[510] = 0x55;
    disk[511] = 0xaa;

    // Place each volume at its partition LBA.
    disk.resize(ntfs_start_lba as usize * SECTOR, 0);
    disk.extend_from_slice(ntfs);
    disk.resize(fat_start_lba as usize * SECTOR, 0);
    disk.extend_from_slice(fat);
    disk
}

#[test]
fn open_all_surfaces_every_partition_of_a_multipartition_disk() {
    let disk = build_mbr_disk(NTFS_VOL, FAT_VOL);

    let dir = std::env::temp_dir().join(format!("fvfs_open_all_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("multipart.img");
    std::fs::write(&path, &disk).unwrap();

    let evidences = Vfs::new()
        .open_all(Path::new(&path))
        .expect("open_all resolves the multi-partition disk");

    // Both partitions must surface as mounted filesystems — not just partition 0.
    let mounted: Vec<_> = evidences.into_iter().filter_map(|e| e.fs).collect();
    assert_eq!(
        mounted.len(),
        2,
        "open_all must surface BOTH partitions as mounted filesystems"
    );

    let kinds: Vec<FsKind> = mounted.iter().map(|fs| fs.kind()).collect();
    assert!(
        kinds.contains(&FsKind::NTFS),
        "an NTFS partition: {kinds:?}"
    );
    assert!(kinds.contains(&FsKind::FAT), "a FAT partition: {kinds:?}");

    // The NTFS volume `open` would have skipped is now reachable and readable.
    let ntfs = mounted
        .iter()
        .find(|fs| fs.kind() == FsKind::NTFS)
        .expect("NTFS partition mounted");
    let id = ntfs
        .lookup(ntfs.root(), b"file1.txt")
        .expect("lookup")
        .expect("file1.txt present in the NTFS partition");
    assert_eq!(id, FileId::NtfsRef { entry: 37, seq: 1 });
    let mut buf = [0u8; 512];
    let n = ntfs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read file1.txt");
    assert_eq!(n, 408);
    assert_eq!(&buf[..15], b"Just some bogus");

    std::fs::remove_dir_all(&dir).ok();
}
