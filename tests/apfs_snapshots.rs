//! Engine snapshot cohort: `Vfs::snapshots` enumerates an APFS volume's
//! snapshots as a time-indexed `[H]` cohort, and `Vfs::open_snapshot(path, xid)`
//! re-mounts one point-in-time state. Ground truth from apfs-forensic (Tier-2
//! real APFS carve): `apfs_volume.bin` is the P4 fixture with ZERO snapshots, so
//! the cohort is empty; the populated fixture is env-gated (needs the macOS
//! snapshot entitlement to mint — see apfs-forensic's tests/data/README.md).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use forensic_vfs_engine::{walk, SnapshotView, Vfs};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apfs_volume.bin");

#[test]
fn apfs_container_without_snapshots_yields_empty_cohort() {
    // The committed P4 fixture has no snapshots: enumeration wires through the
    // container/volume open and returns an empty cohort (never a bootstrap error).
    let views: Vec<SnapshotView> = Vfs::new()
        .snapshots(Path::new(FIXTURE))
        .expect("enumerate snapshots");
    assert!(
        views.is_empty(),
        "P4 fixture has no snapshots; got {views:?}"
    );
}

#[test]
fn populated_fixture_snapshot_cohort_is_reopenable() {
    let Ok(path) = std::env::var("APFS_P5_FIXTURE") else {
        eprintln!("APFS_P5_FIXTURE unset; skipping populated cohort test");
        return;
    };
    let vfs = Vfs::new();
    let views = vfs
        .snapshots(Path::new(&path))
        .expect("enumerate snapshots");
    assert!(
        views.len() >= 2,
        "expected >=2 snapshots in the populated fixture, got {}",
        views.len()
    );

    // Every SnapshotView.locator is re-openable end-to-end: open_snapshot mounts
    // that point-in-time state and walk surfaces its files.
    for v in &views {
        let ev = vfs
            .open_snapshot(Path::new(&path), v.xid)
            .expect("open snapshot by xid");
        let fs = ev.fs.expect("snapshot must mount a filesystem");
        assert!(
            ev.root.to_uri().contains("fs:apfs"),
            "snapshot locator names the APFS layer: {}",
            ev.root.to_uri()
        );
        let entries = walk(fs.as_ref()).expect("walk snapshot");
        assert!(
            !entries.is_empty(),
            "snapshot {} should surface files",
            v.xid
        );
    }

    // The epoch is derived from create_time, so the newest snapshot's epoch
    // strictly exceeds the oldest's (big-endian ns timestamp ordering).
    let newest = views.iter().max_by_key(|v| v.xid).expect("a newest");
    let oldest = views.iter().min_by_key(|v| v.xid).expect("an oldest");
    assert!(
        newest.epoch.0 > oldest.epoch.0,
        "newest epoch must exceed oldest"
    );
}
