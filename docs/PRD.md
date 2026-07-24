# forensic-vfs-engine — Purpose & Scope

`forensic-vfs-engine` is the ORCHESTRATION crate over the
[`forensic-vfs`](https://crates.io/crates/forensic-vfs) contracts: the one place
that depends *down* on every SecurityRonin fleet reader and wires them into a
single detect-and-mount call. It exists so a consumer that reads an evidence image
never hand-codes an image-format ladder and never learns one container or
filesystem format from another — it asks `Vfs::open(path)` and gets back a
read-only `dyn FileSystem`. The design decisions behind it are recorded as ADRs
under [`docs/decisions/`](docs/decisions/).

**Who links it:** the examiner-facing tools (`disk4n6`, Issen) and any fleet
consumer that needs format-agnostic image access. It is a library — it ships no
binary of its own.

**In scope**

- Detect and mount the container → volume-system → filesystem stack of a piece of
  evidence, nesting resolved automatically to a bounded depth
  ([ADR 0001](docs/decisions/0001-orchestration-detect-and-mount-crate.md),
  [ADR 0002](docs/decisions/0002-openers-registry-delegating-to-resolver.md)).
- Register every fleet reader, compiled in and non-optional, so the zero-config
  build resolves the whole stack
  ([ADR 0003](docs/decisions/0003-batteries-included-every-reader-compiled-in.md)).
- Surface every partition of a multi-partition disk (`open_all`), resolve directly
  from a byte source (`open_source`), and walk a mounted filesystem (`walk`).
- Expose APFS snapshots as the `[H]` state-history seam (`snapshots` /
  `open_snapshot`,
  [ADR 0008](docs/decisions/0008-apfs-snapshot-cohort-h-seam.md)).
- Detect full-disk-encrypted volumes by signature; unlock is deferred to the
  resolver's credentialed pass
  ([ADR 0009](docs/decisions/0009-fde-layers-as-signature-probers.md)).

**Non-goals**

- **No binary.** No CLI/GUI/MCP; the front-ends live in their own crates.
- **No format parsing of its own.** Byte decoding belongs to the reader crates;
  the engine only probes and wires (MBR/GPT are the sole in-crate parsers, by the
  build-vs-reuse call in
  [ADR 0007](docs/decisions/0007-in-crate-mbr-gpt-and-probe-disambiguation.md)).
- **No write path.** The `forensic-vfs` contracts are read-only by construction;
  evidence immutability holds without discipline.
- **No decryption in-crate.** FDE readers do the cryptography; the engine registers
  the probers.
- Documented current limits: MBR extended partitions are not chased, and multi-file
  VMDK flat extents are out of scope for the single-stream decoder.

**Validation:** each end-to-end test resolves a fixture — either a real,
oracle-validated artifact (TSK / `hdiutil` / `qemu-img` / `pyewf`) copied from a
reader repo, or a Tier-2 self-minted image — and confirms the known ground-truth
surfaces; the resolver is fuzzed (`fuzz_resolve`). See
[`docs/validation.md`](docs/validation.md).
