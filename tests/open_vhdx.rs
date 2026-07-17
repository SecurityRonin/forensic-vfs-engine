//! Engine end-to-end: `Vfs::open` decodes a VHDX container (`vhdxfile` magic) to
//! its virtual disk, then resolves the NTFS volume inside and mounts it. The
//! fixture wraps the same TSK-validated NTFS volume as the bare-NTFS tests, so
//! the oracle is unchanged: `file1.txt` = 408 bytes beginning "Just some bogus".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, Vfs};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ntfs.vhdx");

#[test]
fn vfs_open_decodes_vhdx_container_to_ntfs() {
    let ev = Vfs::new().open(Path::new(FIXTURE)).expect("open ntfs.vhdx");
    let fs = ev.fs.expect("VHDX->NTFS should resolve to a filesystem");

    let uri = ev.root.to_uri();
    assert!(uri.contains("container:vhdx"), "locator: {uri}");
    assert!(uri.contains("fs:ntfs"), "locator: {uri}");

    let names: Vec<String> = walk(fs.as_ref())
        .expect("walk vhdx->ntfs")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "file1.txt"),
        "walk should surface file1.txt: {names:?}"
    );
}
