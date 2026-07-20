//! `Vfs::open` detects a bare UDF (ISO/UDF optical) volume by its Volume
//! Recognition Sequence — the `BEA01`/`NSR03`/`TEA01` marks at LBA 16 (bytes
//! 32768/34816/36864) — and mounts it as a `dyn FileSystem` through
//! `udf_forensic::vfs::UdfVfs`, the UDF leg of the engine.
//!
//! Fixture: the smallest of `udf-forensic`'s committed `mkudffs` (udftools 2.3)
//! images (`udf_plain.img`), copied here as `udf.img`. Provenance in
//! `tests/data/README.md`; a bare UDF 1.50 volume authored for CD-R media.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs::FsKind;
use forensic_vfs_engine::{walk, Vfs};

const IMG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/udf.img");

#[test]
fn vfs_open_detects_and_mounts_udf() {
    let vfs = Vfs::new();
    let evidence = vfs.open(Path::new(IMG)).expect("open evidence");

    let fs = evidence.fs.expect("engine detected a filesystem");
    assert_eq!(fs.kind(), FsKind::UDF);

    // The mounted UDF root is walkable end-to-end (a real mount, not just a
    // signature match) — `mkudffs` authors an empty root, so the walk is a
    // clean, non-erroring enumeration from the seeded root FE.
    let entries = walk(fs.as_ref()).expect("walk the mounted UDF volume");
    assert!(
        entries.len() < WALK_SANITY_CAP,
        "walk returned an implausible node count: {}",
        entries.len()
    );
}

/// A loose upper bound: the tiny `mkudffs` volume cannot contain thousands of
/// nodes, so a walk that returns more signals a mount/traversal defect.
const WALK_SANITY_CAP: usize = 4096;
