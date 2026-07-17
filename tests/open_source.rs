//! `Vfs::open_source` resolves directly from a byte source (an in-memory buffer,
//! a nested image, a carved region) — not only a path. Proven over the raw
//! TSK-validated NTFS volume presented as a `dyn ImageSource`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use forensic_vfs::{DynSource, FileId, ImageSource, StreamId, VfsResult};
use forensic_vfs_engine::Vfs;

/// Minimal in-memory ImageSource for tests.
struct Mem(Vec<u8>);
impl ImageSource for Mem {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        let Some(src) = self.0.get(off..) else {
            return Ok(0);
        };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }
}

const NTFS_VOL: &[u8] = include_bytes!("data/ntfs_volume.bin");

#[test]
fn open_source_resolves_a_bare_ntfs_volume_from_memory() {
    let src: DynSource = Arc::new(Mem(NTFS_VOL.to_vec()));
    let fs = Vfs::new()
        .open_source(src)
        .expect("resolve")
        .expect("NTFS detected in the in-memory volume");
    let id = fs
        .lookup(fs.root(), b"file1.txt")
        .expect("lookup")
        .expect("file1.txt");
    assert_eq!(id, FileId::NtfsRef { entry: 37, seq: 1 });
    let mut buf = [0u8; 512];
    assert_eq!(fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap(), 408);
    assert_eq!(&buf[..15], b"Just some bogus");
}
