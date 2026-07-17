//! Engine end-to-end: `Vfs::open` resolves an Apple Partition Map (APM) disk.
//! The fixture is a DMG whose decoded disk carries an APM ('ER' DDR + 'PM' map)
//! with an `Apple_HFS` partition; so this exercises the full DMG -> APM -> HFS+
//! recursion. Ground truth from hdiutil: the volume contains `apm.txt`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, Vfs};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apm_hfsplus.dmg");

#[test]
fn vfs_open_resolves_hfsplus_in_an_apm_partition() {
    let ev = Vfs::new().open(Path::new(FIXTURE)).expect("open apm dmg");
    let fs = ev
        .fs
        .expect("DMG -> APM -> HFS+ should resolve to a filesystem");

    let uri = ev.root.to_uri();
    assert!(uri.contains("container:dmg"), "locator: {uri}");
    assert!(
        uri.contains("volume:apm"),
        "locator should record the APM layer: {uri}"
    );
    assert!(uri.contains("fs:hfsplus"), "locator: {uri}");

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk apm->hfs+")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("apm.txt")),
        "walk should surface apm.txt: {names:?}"
    );
}
