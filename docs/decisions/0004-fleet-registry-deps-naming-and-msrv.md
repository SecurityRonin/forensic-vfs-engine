# 4. Fleet crates over registry deps, collision-driven `-core`/`package` renames, capability-driven MSRV

Date: 2026-07-24
Status: Accepted

## Context

Two binding fleet rules shape this crate's dependency posture. "Dependency
Preference — prefer our own crates" mandates SecurityRonin/`h4x0r` crates over
third parties, and the *published registry* crate over a `path` dependency once
one is on crates.io. The "Crate naming grammar" governs bare-name collisions on
crates.io. The MSRV policy splits a published library's low floor from an app's
pinned toolchain — but also states capability yields to MSRV where a needed
capability dep raises it.

## Decision

- **Registry deps, not path deps.** The crate was extracted directly onto
  registry versions (`29bf792`, "on registry deps"); every dependency in
  `Cargo.toml:32-77` is a fleet crate pinned to a published version
  (`ewf = "0.4.1"`, `ntfs-core = "0.9.1"`, `forensic-vfs = "0.7"`,
  `forensic-vfs-resolver = "0.3"`, …), reproducible and decoupled from local
  checkout layout.
- **Collision-driven renames via `package =`.** Where the bare crate name is
  taken or the reader publishes under a `-core` package, the dependency uses
  `package = "<x>-core"` while the import path stays the bare name — `vhd` ⇒
  `vhd-core`, `qcow2` ⇒ `qcow2-core`, `vmdk` ⇒ `vmdk-core`, `vhdx` ⇒ `vhdx-core`,
  `dmg` ⇒ `dmg-core`, `apm` ⇒ `apm-partition-core`, `ext4fs` ⇒ `ext4fs-core`,
  `xfs` ⇒ `xfs-core`, `fat` ⇒ `fat-core`, `iso` ⇒ `iso9660-forensic`, `hfsplus`
  ⇒ `hfsplus-forensic` (`Cargo.toml:45-77`).
- **Capability-driven MSRV floor.** `rust-version = "1.88"` (`Cargo.toml:5`,
  README `Rust 1.88+` badge). Because this crate compiles in the whole reader set
  (ADR 0003), its MSRV is the maximum of that set — it cannot sit at the fleet
  library floor (`1.75`/`1.80`); the batteries-included capability takes
  precedence over a low MSRV, per the constitution.
- **`Cargo.lock` committed** (`b6a4500`, "ci: commit Cargo.lock (deterministic
  vet/deny)") so CI resolves the shipped graph and cargo-vet/deny exemptions stay
  stable, per the fleet lock-commit rule for libraries.

## Consequences

- Consumers get exactly what the registry publishes; a sibling repo rename or move
  never breaks this crate's build.
- Publishing is release-plz's job (`release-plz.toml`, ADR-adjacent), one reviewed
  version-bump PR per wave.
- The high MSRV is a deliberate consequence of the batteries-included mandate, not
  a regression to be lowered.

**Rationale note:** the exact fleet reader that pins the floor to *precisely* 1.88
(versus a lower value) is not identifiable from this repo alone; it is documented
here as the max-of-the-set floor under the constitution's "MSRV yields to
capability", not attributed to a specific dependency.
