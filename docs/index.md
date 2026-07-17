# forensic-vfs-engine

The **forensic-vfs registry + resolver**: one `Vfs::open(path)` that detects the
container / volume-system / filesystem stack of a piece of evidence and mounts a
read-only `dyn FileSystem`. This is the ORCHESTRATION crate over the
[`forensic-vfs`](https://crates.io/crates/forensic-vfs) contracts — the one place
that depends *down* on every fleet reader.

## What it does

Point it at a disk image (raw, EWF/E01, VHD/VHDX, VMDK, QCOW2, DMG, AFF4) and it:

1. Opens the base byte source (an EWF container by path, or a raw file).
2. Recurses the container / volume-system / filesystem layers, sniffing each with
   a small bounded read.
3. Mounts the first filesystem it recognizes as a read-only `dyn FileSystem` and
   records the exact open-recipe in a re-resolvable [`PathSpec`] locator.

A source nothing recognizes yields `Evidence { fs: None }` — a genuinely clean
"unknown", never a silent error.

## Batteries-included

The zero-config build registers every fleet reader:

| Layer | Readers |
|---|---|
| Container | EWF/E01 · VHD · VHDX · VMDK · QCOW2 · DMG · AFF4 |
| Volume system | MBR · GPT · APM |
| Filesystem | NTFS · ext2/3/4 · XFS · ISO 9660 · APFS · HFS+/HFSX · exFAT · FAT12/16/32 |

## Quick start

```rust
use forensic_vfs_engine::{walk, Vfs};
use std::path::Path;

let evidence = Vfs::new().open(Path::new("disk.E01"))?;
if let Some(fs) = evidence.fs {
    for entry in walk(fs.as_ref())? {
        println!("{}", String::from_utf8_lossy(entry.path.last().unwrap_or(&Vec::new())));
    }
}
# Ok::<(), forensic_vfs::VfsError>(())
```

## Snapshots (`[H]` state-history)

`Vfs::snapshots(path)` enumerates an APFS volume's snapshots as a time-indexed
cohort (`Vec<SnapshotView>`), each carrying an `EpochTag` and a re-openable
locator; `Vfs::open_snapshot(path, xid)` mounts one. Evidence with no APFS
filesystem yields an empty cohort — a clean "no snapshots here", not an error.

## Trust but verify

- **Panic-free by lint** — `unsafe_code = forbid`, `clippy::unwrap_used` /
  `expect_used = deny` across production code.
- **Input-fuzzed** — the resolver has a `cargo-fuzz` target driving `open_source`
  over arbitrary bytes; resolving attacker-controllable disk bytes must never panic.
- **Validated against real artifacts** — see [Validation](validation.md).

[`PathSpec`]: https://docs.rs/forensic-vfs/latest/forensic_vfs/struct.PathSpec.html
