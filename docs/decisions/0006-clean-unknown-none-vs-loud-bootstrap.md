# 6. Unrecognized source ⇒ `fs: None`; bootstrap/decode failure ⇒ loud error

Date: 2026-07-24
Status: Accepted

## Context

The fleet Robustness rule "Bootstrap failure ≠ artifact-not-found" is binding: a
genuine per-artifact miss may degrade to empty, but a failure in the prerequisite
chain must be loud and never absorbed into an empty/"none found" result. For a
detect-and-mount engine the distinction is sharp — "nothing here recognizes this
source" and "a recognized source failed to decode" must not collapse into the same
value.

## Decision

- **Clean unknown ⇒ `None`.** A source no registered prober claims returns
  `Evidence { fs: None }`, "a genuinely clean unknown, not an error"
  (`src/lib.rs:59-72`). `open_source` likewise returns `Ok(None)`
  (`src/lib.rs:147-153`).
- **Positive probe that then fails ⇒ loud error.** Once a prober says `Yes`/`Maybe`
  and its reader fails, the error propagates as `VfsError::Decode`, never a silent
  `None` — pinned by tests: NTFS magic over garbage
  (`ntfs_magic_but_invalid_boot_is_a_loud_error`, `src/lib.rs:1598-1604`), garbage
  container bodies (`src/lib.rs:1678-1731`), a bad `.E01`
  (`a_garbage_e01_path_fails_loud`, `src/lib.rs:1606-1612`).
- **`Maybe` must not turn a clean unknown into an error.** `BtrfsProbe` returns
  `Confidence::Yes` when it sees the `_BHRfS_M` superblock magic (offset `0x10040`,
  65600) and `Confidence::No` otherwise — never `Maybe`. That offset sits inside the
  resolver's 128 KiB head sniff window (`SNIFF_CAP` = `128 * 1024`), so btrfs is
  auto-detected end-to-end (proven by `vfs_detects_and_mounts_btrfs_from_the_superblock`,
  `tests/open_btrfs.rs`). It deliberately does **not** return `Maybe`: a `Maybe`
  would run `BtrfsFs::open` on every otherwise-unrecognized source, and that errors
  on a non-btrfs image, converting the "empty container ⇒ `None`" contract into a
  loud error on e.g. an all-zero decoded container (`src/lib.rs:660-698`).
- **State-history surface honors the same split.** `snapshots` on a
  non-APFS/unrecognized source is an **empty** cohort (`src/lib.rs:169-186`), while
  `open_snapshot` fails loud: `VfsError::Bootstrap` when nothing mounts,
  `Unsupported` on a non-APFS filesystem, `Decode` on an unknown `xid`
  (`src/lib.rs:200-232`).

## Consequences

- A consumer can trust that `fs: None` means "clean unknown", and that any error
  is a real failure worth surfacing.
- btrfs is auto-detected: its superblock magic (offset 65600) falls inside the
  resolver's 128 KiB head sniff window, so the prober returns a decisive `Yes`/`No`
  rather than a `Maybe` that would break the clean-unknown ⇒ `None` contract.
