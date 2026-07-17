//! Engine end-to-end: `Vfs::open` detects an Apple UDIF disk image by its `koly`
//! trailer (at `file_len - 512`, matched via the tail sniff window), decodes it
//! to its virtual disk, and mounts the bare HFS+ volume inside.
//!
//! Fixture: `hfsplus.dmg`, minted on macOS with
//! `hdiutil create -srcfolder <dir-with-HELLO.txt> -fs HFS+ -volname VFSHFS
//! -layout NONE hfsplus.dmg` (bare HFS+, no partition map — so it resolves
//! without APM support). Oracle: `hdiutil imageinfo` reports Sector Count 3714
//! (⇒ virtual disk 3714 × 512 = 1,901,568 bytes) and the root holds `HELLO.txt`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, Vfs};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfsplus.dmg");

#[test]
fn vfs_open_decodes_dmg_to_its_hfsplus_payload() {
    let ev = Vfs::new()
        .open(Path::new(FIXTURE))
        .expect("open dmg fixture");
    let fs = ev.fs.expect("DMG should decode to an HFS+ filesystem");

    let uri = ev.root.to_uri();
    assert!(
        uri.contains("container:dmg"),
        "locator should record the DMG container: {uri}"
    );
    assert!(
        uri.contains("fs:hfsplus"),
        "locator should record the HFS+ payload: {uri}"
    );

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk hfs+ payload")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("HELLO.txt")),
        "walk should surface HELLO.txt from inside the DMG: {names:?}"
    );
}

#[test]
fn dmg_decodes_to_the_oracle_virtual_disk_size() {
    // Decoder-level cross-check against the hdiutil oracle (Sector Count 3714).
    let f = std::fs::File::open(FIXTURE).expect("open dmg file");
    let reader = dmg::DmgReader::open(f).expect("parse koly trailer");
    assert_eq!(reader.virtual_disk_size(), 3714 * 512);
}
