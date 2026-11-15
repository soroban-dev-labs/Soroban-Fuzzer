# Changelog

## Unreleased

- `LedgerJumps` has a new `seconds_per_ledger` field (default 5) that sets how far the ledger timestamp moves per ledger jumped. **Breaking:** code that builds `LedgerJumps { .. }` with a struct literal must add the field or end with `..LedgerJumps::default()`.
- New `advance_ledgers_with(env, ledgers, seconds_per_ledger)`. `advance_ledgers(env, ledgers)` keeps its signature and still uses 5 seconds per ledger.

## 0.1.0 (2026-11-02)

First release.

- `Harness` trait and `Fuzzer` runner: random action sequences with ledger time jumps, shrinking to a minimal case, and seeded replay (`SOROBAN_FUZZ_SEED`).
- Checks for missing `require_auth` (`MissingAuth`), auth that is recorded but not enforced (`AuthBypass`, via `check_unsigned_calls`), expired persistent and instance entries (`ArchivedEntry`), invariant and model mismatches, panics, and per-call resource use against a share of mainnet limits.
- Coverage-guided mode for cargo-fuzz and libFuzzer (`Fuzzer::fuzz_one`).
- Harness helpers: `check_call`, `Outcome::if_executed`, `expect_unless`, `Balances`, `ensure_eq!`, `TestToken`, and the `relative_amount` strategy.
- Side-effect-free TTL and storage inspection (`ttl`, `storage`).
