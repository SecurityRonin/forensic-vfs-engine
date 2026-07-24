# 3. Batteries-included — every fleet reader compiled in, non-optional

Date: 2026-07-24
Status: Accepted

## Context

The fleet "Batteries-Included" rule is binding: an analyst on an evidence
workstation cannot `cargo build --features …`, so a capability that is not
compiled in is a capability that is not there when it matters. `default-features
= false` as a way to slim a fleet dependency is banned; when full features trip a
gate, the gate is fixed, not the feature set.

As the ORCHESTRATION crate (ADR 0001), this is precisely the crate where that
rule applies hardest — it is the one place expected to resolve the *whole*
container/volume/filesystem stack out of the box.

## Decision

Every reader is a hard, non-optional dependency, each pulling its `vfs` adapter
feature (`Cargo.toml:32-77`, comment at lines 39-42: "Batteries-included: every
fleet reader is compiled in, non-optional, so the zero-config build resolves the
whole container/volume/filesystem stack"):

- Containers: `ewf`, `vhd`, `qcow2`, `vmdk`, `vhdx`, `dmg`, `aff4`.
- Volume systems: `apm` (MBR/GPT are in-crate, ADR 0007).
- Filesystems: `ntfs-core`, `ext4fs`, `xfs`, `iso9660-forensic`, `apfs-core`,
  `hfsplus-forensic`, `fat-core`, `btrfs-core`, `ufs-core`, `udf-forensic`.
- Archive peel: `archive-core` (gzip/bzip2/tar/zip/7z).
- FDE: `bitlocker-core`, `luks-core`, `filevault-core`, `veracrypt-core` (ADR 0009).

Where the full feature set trips the license gate, the gate is widened rather than
the capability amputated: `deny.toml` allows `BSL-1.0` and `CC0-1.0` (blazehash's
`xxhash-rust` / `tiny-keccak`) and `bzip2-1.0.6` / `MIT-0` (archive-core's
7z/bzip2 path), each with an inline comment saying so (`deny.toml`, `[licenses]`).

## Consequences

- The zero-config build detects and mounts the entire fleet stack — no
  `--features` dance in the field.
- The dependency tree is large and the MSRV floor is high (ADR 0004); both are
  accepted trade-offs, not defects.
- New readers are added to `default_openers` and to `Cargo.toml` together; the
  license allowlist grows as new permissive-licensed transitive capabilities
  arrive, and is fixed in `deny.toml`, never worked around by slimming.
