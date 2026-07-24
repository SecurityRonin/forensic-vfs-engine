# 7. In-crate MBR/GPT parsers, external APM, and boot-sector-aware probe disambiguation

Date: 2026-07-24
Status: Accepted

## Context

Volume-system detection has a well-known trap: the `0x55AA` boot signature at
offset 510 is present in an MBR, but *also* in a bare exFAT/NTFS/FAT filesystem
boot sector. A naive "`0x55AA` + one plausible-looking entry" heuristic misreads a
bare filesystem volume as a partition table, so `open_all` tries to enumerate
partitions that do not exist and drops the real filesystem. The git history shows
this being caught and fixed: `3aa86e7` ("test(open_all): RED — MBR probe misreads
exFAT/NTFS/FAT boot sectors") → `e419016` ("fix(open_all): require valid partition
table, reject FS boot sectors in MBR probe").

Separately, a build-vs-reuse call: MBR and GPT tables are small, stable, fully
specified structures; APM parsing is already published as a fleet reader.

## Decision

- **MBR and GPT are parsed in-crate; APM delegates to the fleet reader.**
  `Mbr::parse` / `Gpt::parse` decode the tables directly (`src/lib.rs:751-920`);
  `ApmProbe`/`Apm::parse` hand a bounded head window to `apm::parse`
  (`apm-partition-core`, `src/lib.rs:957-996`). `Cargo.toml:53` records the split:
  "MBR + GPT are pure in-crate parsers; APM is external".
- **MBR probe disambiguation.** `MbrProbe::probe` treats `0x55AA` as necessary but
  not sufficient: it declines when an ASCII filesystem identifier is present at
  offset 3 (`EXFAT   ` / `NTFS    `) or a FAT jump instruction (`0xEB`/`0xE9`) sits
  at offset 0, and requires a structurally valid partition entry (valid boot flag,
  non-zero non-protective type, non-zero size) before claiming an MBR
  (`src/lib.rs:709-744`). It also ignores the `0xEE` protective marker so GPT takes
  over (`src/lib.rs:737`, `810-812`). Both directions are pinned by
  `mbr_probe_rejects_filesystem_boot_sectors` (`src/lib.rs:1533-1595`).
- **GPT allocation bomb guards.** Entry count is capped at 256 and entry size
  clamped to `128..=512` before allocating the entry array; reversed/unused entries
  are skipped (`src/lib.rs:856-890`).

## Consequences

- A bare exFAT/NTFS/FAT volume falls through to a single-filesystem open instead of
  being shredded into phantom partitions; a genuine MBR still probes `Yes`.
- This is a general disambiguation rule (a property of boot sectors), not an
  `if input == fixture` special case — it holds for filesystem boot sectors the
  test never enumerated.
- MBR extended partitions (types `0x05`/`0x0f`) are not yet chased
  (`src/lib.rs:700-701`); a documented scope limit, not a defect.
