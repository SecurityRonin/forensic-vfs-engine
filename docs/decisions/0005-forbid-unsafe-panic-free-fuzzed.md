# 5. `forbid(unsafe)`, panic-free by lint, resolver fuzzed

Date: 2026-07-24
Status: Accepted

## Context

The engine resolves attacker-controllable disk bytes — MBR/GPT partition tables,
filesystem boot sectors, container headers — over arbitrary input. The fleet
"Paranoid Gatekeeper" standard requires such crates to never panic, never read out
of bounds, and never trust a length field, backed by the panic-free lint recipe
plus a fuzz target. The `unsafe` policy allows a bounded `deny` + per-site
`#[allow]` exception only where a reader genuinely needs one (e.g. an `mmap`);
this engine performs no such operation itself — the readers own their bounded
`unsafe` behind their own crates.

## Decision

- **`unsafe_code = "forbid"`** (`Cargo.toml:82-83`). The crate can wear the
  strongest posture — a provable "zero places a crafted input can corrupt memory"
  — precisely because it delegates all byte decoding to the reader crates and does
  no `mmap`/FFI of its own. It earns the README `unsafe forbidden` badge honestly.
- **Panic-free by lint:** `clippy::unwrap_used = "deny"` and
  `expect_used = "deny"` across production code (`Cargo.toml:85-88`), with tests
  exempted (`#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]`,
  `src/lib.rs:8`). The in-crate parsers read through bounds-checked helpers and
  saturating/`checked_*` arithmetic (e.g. GPT bomb guards, `src/lib.rs:856-861`).
- **Fuzzed:** `fuzz_resolve` drives `Vfs::open_source` over arbitrary bytes; the
  invariant is "resolving attacker-controllable disk bytes must never panic"
  (`fuzz/fuzz_targets/fuzz_resolve.rs`). Each underlying reader carries its own
  per-structure fuzz targets.

## Consequences

- The differentiator claim is *input-fuzzed* (measured); *panic-free* appears only
  as the qualified static half ("panic-free by lint"), per the fleet
  evidence-based-rigor wording rule (README "Trust but verify").
- Any future need for in-crate `unsafe` would require downgrading `forbid` to
  `deny` plus a justified per-site allow — a conscious, reviewable change, not a
  silent one.
