# 1. forensic-vfs-engine is the single detect-and-mount ORCHESTRATION crate

Date: 2026-07-24
Status: Accepted

## Context

The fleet's VFS policy (`~/src/ronin-issen/CLAUDE.md`, "VFS & Universal Container
Abstraction") is binding: *a consumer that reads an evidence image MUST NOT know
one container or filesystem format from another.* `forensic-vfs` is the
KNOWLEDGE-leaf contract crate (the `ImageSource` edge plus the
container/volume-system/crypto/filesystem probe traits and the `Locator`
locator); it defines the vocabulary but composes no concrete decoders. Something
has to be the one place that wires every reader together so a consumer can call a
single open-any-image entry point instead of hand-coding an image-format ladder.

This crate was extracted for exactly that role — commit `29bf792`
("feat: extract forensic-vfs-engine as a standalone crate on registry deps"),
2026-07-17 — and its module doc states it plainly: "This is the ORCHESTRATION
crate — the one place that depends *down* on every fleet reader"
(`src/lib.rs:1-6`).

## Decision

`forensic-vfs-engine` is the concrete engine over the `forensic-vfs` contracts.
It exposes one handle, `Vfs`, with the whole fleet registered by default
(`Vfs::new` → `default_openers`, `src/lib.rs:46-53`, `299-331`), and a small
detect-and-mount surface:

- `Vfs::open(path)` — resolve the base source, descend the
  container/volume/filesystem stack, mount the first filesystem (`src/lib.rs:59-72`).
- `Vfs::open_all(path)` — surface every partition of a multi-partition disk
  (`src/lib.rs:93-143`).
- `Vfs::open_source(DynSource)` — resolve directly from a byte source
  (`src/lib.rs:147-153`).
- `Vfs::snapshots` / `Vfs::open_snapshot` — the `[H]` state-history seam (ADR 0008).
- `walk(fs)` — the triage traversal a consumer runs over the mounted filesystem
  (`src/lib.rs:1357-1385`).

Consumers depend on this engine (or on `forensic-vfs`), never on a per-format
container or per-filesystem crate.

## Consequences

- Adding a new format is a change here; every consumer gains it at once, and no
  consumer carries an `if ewf { … }` special case (the smell the fleet policy
  exists to catch).
- This crate is, by construction, the fleet's single "depends on everything"
  node — the heaviest dependency tree in the fleet and the highest MSRV floor
  (ADR 0003, ADR 0004). That cost is accepted as the price of the abstraction.
- The crate publishes as a library via release-plz (`release-plz.toml`); it ships
  no binary. The examiner-facing tools (`disk4n6`, Issen) link it.
