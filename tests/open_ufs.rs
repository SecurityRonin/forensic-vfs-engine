//! `Vfs::open` detects a bare UFS2/FFS volume by its `fs_magic` (`0x19540119`,
//! at absolute offset 66908) and mounts it as a `dyn FileSystem` through
//! `ufs::vfs::UfsFs` — the UFS leg of the engine. `Vfs::open_all` also exercises
//! the bare-volume fallback (a source no volume system claims resolves to a
//! single filesystem).
//!
//! Fixture: the UFS2 partition extracted from `ufs-forensic`'s `ufs2.raw`
//! BSD-disklabel image at its partition base (byte 8192 = sector 16), re-based to
//! offset 0 so the magic lands at 66908 within the resolver's head window (the
//! engine registers no BSD-disklabel volume system). Provenance +
//! extraction command in `tests/data/README.md`.
//! Oracle: The Sleuth Kit on the source partition (`fls -o 16 -f ufs2 -r`) —
//! root inode 2 holds `passwords.txt`, `a_directory`, `a_link`, `.snap`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::FsKind;
use forensic_vfs_engine::{walk, Vfs};

const IMG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ufs.img");

fn root_names(fs: &dyn forensic_vfs::FileSystem) -> Vec<String> {
    walk(fs)
        .expect("walk ufs")
        .into_iter()
        .filter_map(|e| {
            e.path
                .last()
                .map(|n| String::from_utf8_lossy(n).to_string())
        })
        .collect()
}

#[test]
fn vfs_open_detects_and_mounts_bare_ufs2() {
    let vfs = Vfs::new();
    let evidence = vfs.open(Path::new(IMG)).expect("open evidence");

    let fs = evidence.fs.expect("engine detected a filesystem");
    assert_eq!(fs.kind(), FsKind::UFS);

    let names = root_names(fs.as_ref());
    assert!(
        names.iter().any(|n| n == "passwords.txt"),
        "walk should surface the TSK-known root file passwords.txt: {names:?}"
    );
}

/// `open_all` over a bare volume that no volume system claims falls through to
/// the single-filesystem resolve, yielding exactly one mountable `Evidence`.
#[test]
fn vfs_open_all_falls_back_to_the_single_ufs_filesystem() {
    let evidence = Vfs::new()
        .open_all(Path::new(IMG))
        .expect("open_all evidence");
    assert_eq!(evidence.len(), 1, "one bare UFS volume ⇒ one Evidence");
    let fs = evidence[0].fs.as_ref().expect("mounted filesystem");
    assert_eq!(fs.kind(), FsKind::UFS);
}
