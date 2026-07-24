# 2. A registry of probe→open openers, with recursion delegated to forensic-vfs-resolver

Date: 2026-07-24
Status: Accepted

## Context

Detecting a layered evidence stack (`EWF → GPT → NTFS`, `DMG → APM → HFS+`,
`AFF4(Zip) → ext4`) needs a recursive resolver: sniff a bounded window, ask each
registered prober for a `Confidence`, open the winning layer, and recurse into
the decoded child until a filesystem mounts or nothing claims the bytes.

Early on this crate carried *its own* copy of that recursion. That duplicated the
generic layer-descent logic the fleet already publishes in
`forensic-vfs-resolver` — a DRY violation against the fleet "prefer our own
crates" rule. The git history records the correction: `2f17f5d`
("test(resolve): golden engine==Registry::resolve equivalence"), `7c0988e`
("refactor(resolve): delete engine's duplicate resolver, delegate to
Registry::resolve"), and `5f4ae5a` ("refactor(engine)!: rename wrapper impls to
\*Open, repoint onto forensic-vfs-resolver SourceOpen").

## Decision

The engine owns only the **registry of probers** and the per-format **wrappers**;
the **recursion** lives once, in the resolver.

- `default_openers()` builds an `Openers` by registering a prober per layer:
  eleven `FileSystemOpen`, three `VolumeSystemOpen`, six `ContainerOpen`, one
  `ArchiveOpen`, four `EncryptionOpen` (`src/lib.rs:303-331`).
- Each wrapper implements the matching `forensic_vfs` `*Open` trait — a `probe`
  returning `Confidence::{Yes,Maybe,No}` over a `SniffWindow`, and an `open` that
  hands off to the fleet reader (e.g. `NtfsProbe`, `src/lib.rs:357-382`).
- The recursive descent is `forensic_vfs_resolver::SourceOpen::open`
  (`self.openers.open(base, spec, depth)`, `src/lib.rs:23`, `62`, `130`, `152`);
  the engine never re-implements it.
- A golden test pins that the engine path and a direct `Openers::open` mount the
  identical filesystem, so any future divergence fails a test rather than shipping
  silently (`engine_resolution_matches_openers_open_directly`, `src/lib.rs:1980`).

## Consequences

- One resolver implementation is shared fleet-wide; the engine shrinks to probers
  plus wiring.
- `Confidence` drives ordering and cost: `Yes` mounts directly, `Maybe` defers to
  `open` for disambiguation (AFF4 vs a plain Zip, `src/lib.rs:1214-1220`;
  VeraCrypt, ADR 0009), `No` declines.
- Prober registration order is load-bearing where signatures overlap — `ExFatProbe`
  is registered before `FatProbe` because exFAT zeroes the legacy BPB fields the
  FAT probe keys on (`src/lib.rs:311-312`, `534-537`).
