//! Engine end-to-end: `Vfs` auto-detects an XFS volume through the same probe
//! registry as NTFS/ext4/APFS/… and mounts it as a `dyn FileSystem`.
//!
//! Two tiers:
//! - **Always-on (committed fixture):** the real v5.img superblock sector
//!   (`xfs_superblock.bin`) is sniffed by the registered XFS probe and mounted,
//!   proving `FsKind::XFS` detection + the `fs:xfs` locator without shipping the
//!   512 MiB volume.
//! - **Env-gated real walk (`XFS_ORACLE_V5_IMG`):** when the full v5.img oracle
//!   is present (owned by `xfs-forensic`; consumed here via the env var — the
//!   fleet corpus-sharing convention, since a `mkfs.xfs` image cannot be minted
//!   small enough to commit), the engine walks the mounted filesystem and
//!   surfaces the known root entries. Skips cleanly when the image is absent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use forensic_vfs::{DynSource, FsKind, ImageSource, VfsResult};
use forensic_vfs_engine::{walk, Vfs};

/// Minimal in-memory ImageSource for the committed-superblock detection test.
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

/// The real v5.img superblock sector (`XFSB` magic, blocksize 4096) — committed
/// so the detection leg always runs (see the module docs).
const XFS_SB: &[u8] = include_bytes!("data/xfs_superblock.bin");

#[test]
fn vfs_detects_and_mounts_xfs_from_the_superblock() {
    let src: DynSource = Arc::new(Mem(XFS_SB.to_vec()));
    let fs = Vfs::new()
        .open_source(src)
        .expect("resolve")
        .expect("engine detected XFS from the XFSB superblock");
    assert_eq!(fs.kind(), FsKind::XFS);
}

/// Resolve the full v5 oracle image (owned by `xfs-forensic`) via
/// `XFS_ORACLE_V5_IMG`, else the sibling checkout's `tests/data/v5.img`.
fn v5_image_path() -> Option<PathBuf> {
    let p = std::env::var("XFS_ORACLE_V5_IMG").map_or_else(
        |_| PathBuf::from("../../../xfs-forensic/tests/data/v5.img"),
        PathBuf::from,
    );
    p.exists().then_some(p)
}

#[test]
fn vfs_open_walks_the_real_xfs_volume() {
    let Some(path) = v5_image_path() else {
        eprintln!("skip: v5 XFS image absent (set XFS_ORACLE_V5_IMG)");
        return;
    };
    let ev = Vfs::new().open(Path::new(&path)).expect("open v5.img");
    let fs = ev.fs.expect("XFS should resolve to a filesystem");
    assert!(
        ev.root.to_uri().contains("fs:xfs"),
        "locator names the XFS layer: {}",
        ev.root.to_uri()
    );

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk xfs")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    // Known v5.img root entries (xfs-forensic tests/data/README.md P4 oracle).
    for known in ["sf", "block", "big.bin"] {
        assert!(
            names.iter().any(|n| n == known),
            "walk missing {known}: {names:?}"
        );
    }
    // The capstone file, reached by the recursive walk under sf/.
    assert!(
        names.iter().any(|n| n == "file1.txt"),
        "walk should surface sf/file1.txt: {names:?}"
    );
}
