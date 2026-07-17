//! Engine end-to-end: `Vfs::open` detects a bare APFS container (NXSB magic) and
//! mounts it as a `dyn FileSystem`. Ground truth from apfs-forensic (Tier-2 real
//! APFS carve, macOS shasum oracle): `/plain.txt` is present in the root.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, Vfs};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apfs_volume.bin");

#[test]
fn vfs_open_detects_and_mounts_apfs() {
    let ev = Vfs::new()
        .open(Path::new(FIXTURE))
        .expect("open apfs fixture");
    let fs = ev.fs.expect("APFS should resolve to a filesystem");

    // The detected-stack locator names the APFS layer.
    assert!(
        ev.root.to_uri().contains("fs:apfs"),
        "locator: {}",
        ev.root.to_uri()
    );

    // walk surfaces the known file (real APFS content).
    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk apfs")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "plain.txt"),
        "walk should surface plain.txt: {names:?}"
    );
}
