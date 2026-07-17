//! Engine end-to-end: `Vfs::open` detects a exFAT volume and mounts it.
//! Ground truth from TSK on the minted fixture: the root holds `HELLO.TXT`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, Vfs};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/exfat.img");

#[test]
fn vfs_open_detects_and_mounts_exfat() {
    let ev = Vfs::new().open(Path::new(FIXTURE)).expect("open exfat.img");
    let fs = ev.fs.expect("exFAT should resolve to a filesystem");
    assert!(
        ev.root.to_uri().contains("fs:exfat"),
        "locator: {}",
        ev.root.to_uri()
    );

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk exfat")
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
