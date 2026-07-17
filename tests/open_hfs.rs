//! Engine end-to-end: `Vfs::open` detects a bare HFS+ volume (H+/HX signature at
//! offset 1024) and mounts it. Ground truth from hfsplus-forensic (Tier-1, TSK
//! oracle): the root lists `HELLO.TXT`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, Vfs};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfsplus_volume.bin");

#[test]
fn vfs_open_detects_and_mounts_hfsplus() {
    let ev = Vfs::new()
        .open(Path::new(FIXTURE))
        .expect("open hfs+ fixture");
    let fs = ev.fs.expect("HFS+ should resolve to a filesystem");

    assert!(
        ev.root.to_uri().contains("fs:hfsplus"),
        "locator: {}",
        ev.root.to_uri()
    );

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk hfs+")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("HELLO.TXT")),
        "walk should surface HELLO.TXT: {names:?}"
    );
}
