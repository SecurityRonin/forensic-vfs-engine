//! `walk` recursively enumerates a mounted `dyn FileSystem` — the capability a
//! triage consumer needs to actually USE the engine. Proven across all three
//! filesystems (NTFS-in-E01, ext4, ISO 9660), each surfacing its known file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, Vfs};

#[test]
fn walk_enumerates_the_mounted_tree_for_every_filesystem() {
    let cases = [
        ("ntfs_sample.E01", "file1.txt"),
        ("ext4.img", "hello.txt"),
        ("test.iso", "hello.txt"),
    ];
    for (img, wanted) in cases {
        let path = format!("{}/tests/data/{img}", env!("CARGO_MANIFEST_DIR"));
        let ev = Vfs::new().open(Path::new(&path)).expect("open evidence");
        let fs = ev.fs.expect("a filesystem");
        let entries = walk(fs.as_ref()).expect("walk");
        // FS names are raw bytes: ISO 9660 uppercases and appends a ";1" version,
        // so normalize (strip the version, lowercase) for the cross-FS comparison.
        let norm = |c: &[u8]| -> Vec<u8> {
            c.split(|&b| b == b';')
                .next()
                .unwrap_or(c)
                .to_ascii_lowercase()
        };
        assert!(
            entries
                .iter()
                .filter_map(|e| e.path.last())
                .any(|c| norm(c) == wanted.as_bytes()),
            "{img}: walk should surface {wanted} (found {} entries: {:?})",
            entries.len(),
            entries
                .iter()
                .filter_map(|e| e.path.last())
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
        );
    }
}
