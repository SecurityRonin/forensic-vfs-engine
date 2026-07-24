# 8. APFS snapshots exposed as the `[H]` state-history seam

Date: 2026-07-24
Status: Accepted

## Context

The fleet architecture defines a cross-cutting `[H]` state-history functor: each
base primitive lifts to a time-indexed variant, and the shared types
(`TemporalCohort<H>`, `EpochTag`, …) live in `state-history-forensic`. APFS
volumes carry retained snapshots — a natural point-in-time cohort. The engine
already resolves a path down to its APFS filesystem for a normal mount, so it is
the right place to expose that cohort; the full generic `HistoricalSource` /
`TemporalCohort<H>` wiring, however, is not yet built fleet-wide.

## Decision

Expose a minimal, honestly-scoped `[H]` seam now, shaped so it can grow into the
generic cohort later without breaking callers:

- `Vfs::snapshots(path) -> Vec<SnapshotView>` resolves the path through any
  container/volume nesting to its APFS filesystem, then lists the
  snapshot-metadata tree via `apfs_core::vfs::ApfsFs::snapshots`
  (`src/lib.rs:169-186`). Each `SnapshotView` carries an `EpochTag`, the
  transaction `xid`, the name, and a re-openable `Locator`
  (`src/lib.rs:238-274`). The doc comment states the seam explicitly: this is "the
  list form of the richer `state_history_forensic::TemporalCohort<H>`, adopted here
  once the generic `HistoricalSource` wiring lands" (`src/lib.rs:160-165`).
- `Vfs::open_snapshot(path, xid) -> Evidence` re-mounts one snapshot end-to-end via
  `ApfsFs::open_snapshot`, topping the locator with `Layer::Snapshot`
  (`src/lib.rs:200-232`).
- `EpochTag` is derived from the snapshot `create_time` by placing the big-endian
  nanosecond timestamp in the low 8 bytes of the 32-byte tag — simple, reversible
  (round-trips), and correctly ordering (a later time yields a
  lexicographically greater tag) (`epoch_from_create_time`, `src/lib.rs:281-285`;
  pinned by `epoch_from_create_time_round_trips_and_orders`, `src/lib.rs:1881`).
- `state-history-forensic` is a direct dependency (`Cargo.toml:37`) for `EpochTag`.

## Consequences

- Callers get a time-ordered, re-openable snapshot cohort today; the return type
  can be swapped to `TemporalCohort<H>` when the generic wiring lands, with the
  per-view fields already in place.
- The seam is APFS-specific for now; other `[H]` sources (VSS, Time Machine,
  hiberfil chains) are out of scope here and belong in their own `[H]` crates.
- The `EpochTag` encoding is a deliberate, documented convention — not the final
  `ClockProvenance`-rich form, which will arrive with the generic types.
