# soroban-fuzzer

Stateful fuzzing for [Soroban](https://developers.stellar.org/docs/build/smart-contracts) smart contracts, running inside the `soroban-sdk` test environment.

You describe what users can do to your contract and what must always hold. The fuzzer generates random sequences of calls, inserts ledger time jumps between them, and checks each step for Soroban-specific bugs. When a check fails, it shrinks the sequence to a minimal reproduction:

```text
soroban-fuzzer found a failing case: ArchivedEntry
  hint: an entry expired: extend its TTL on access (or use a longer TTL)
  minimal sequence (2 steps):
      0: Deposit(ActorId(0), All)
      1: <advance 4096 ledgers>  <-- failed here
  error: 1 entry expired at ledger 4096:
    Persistent entry of CAAA…OLZM key=Vec([Symbol(Balance), Address(…)]) (live until ledger 4095)
  replay: SOROBAN_FUZZ_SEED=1 cargo test
```

It runs in two modes that share one harness:

- **Property-based mode** (`Fuzzer::check`) runs in `cargo test` on stable Rust, with seeded, reproducible runs and automatic shrinking.
- **Coverage-guided mode** (`Fuzzer::fuzz_one`) runs under [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer, so code-coverage feedback steers the generated sequences toward unexplored contract paths.

## What it catches

| Failure kind | Bug class | How it is detected |
|---|---|---|
| `MissingAuth` | missing `require_auth()` | Each address returned by `required_auths()` must have signed one of the step's calls. |
| `AuthBypass` | auth recorded but not enforced | With `check_unsigned_calls()`, each signed action is first replayed with **no signatures** on a clone of the harness. Any ledger change fails the case. |
| `ArchivedEntry` | missing or too-short `extend_ttl` | After every ledger move, the raw ledger is scanned for persistent or instance entries that have expired. |
| `InvariantViolated` | data loss, e.g. balances kept in `temporary()` storage | Your invariants are checked after every step, including time jumps. |
| `ModelMismatch` | logic bugs | The contract's result differs from your model's. |
| `UnexpectedPanic` | overflow, `unwrap`, contract traps | Panics while applying an action are caught and reported. |
| `ResourceBudgetExceeded` | unbounded loops, reads that grow with state | Every recorded call is compared with a budget for CPU, memory, footprint entries, bytes and events (default 75% of mainnet limits). |
| `ResourceLimitExceeded` | calls that already fail on mainnet | The host reported `Error(Budget, ExceededLimit)`. |

> **Why scan for expiry instead of waiting for a failed read?** Since protocol 23, Soroban restores archived entries automatically when they are accessed. In the test environment, reading an expired entry therefore succeeds silently. Even the SDK's `get_ttl` restores it. The fuzzer reads the host's raw storage map instead, which sees expiry without changing anything. The `ttl` and `storage` modules give your invariants the same side-effect-free view.

## Quick start

```toml
[dev-dependencies]
soroban-fuzzer = "0.1"
soroban-sdk = { version = "29", features = ["testutils"] }
```

This example is compiled and run as part of the crate's tests:

```rust
use std::collections::BTreeMap;
use soroban_fuzzer::prelude::*;
use soroban_sdk::{contract, contractimpl};

// The contract under test: per-user counters.
#[contract]
pub struct Counter;

#[contractimpl]
impl Counter {
    pub fn __constructor(env: Env) {
        env.storage().instance().extend_ttl(200_000, 200_000);
    }

    pub fn add(env: Env, user: Address, n: u32) -> u32 {
        user.require_auth();
        let store = env.storage().persistent();
        let value = store.get::<_, u32>(&user).unwrap_or(0) + n;
        store.set(&user, &value);
        store.extend_ttl(&user, 200_000, 200_000);
        env.storage().instance().extend_ttl(200_000, 200_000);
        value
    }
}

// What a user can do.
#[derive(Clone, Debug)]
enum Action {
    Add(ActorId, u32),
}

// The harness: the contract, its users and a model of the expected state.
#[derive(Clone)]
struct CounterFuzz {
    id: Address,
    actors: Actors,
    model: BTreeMap<ActorId, u32>,
}

impl Harness for CounterFuzz {
    type Action = Action;

    fn setup(env: &Env) -> Self {
        Self {
            id: env.register(Counter, ()),
            actors: Actors::generate(env, 3),
            model: BTreeMap::new(),
        }
    }

    fn actions() -> BoxedStrategy<Action> {
        (actor(3), 0u32..1_000).prop_map(|(a, n)| Action::Add(a, n)).boxed()
    }

    fn apply(&mut self, env: &Env, action: &Action) -> Result<Outcome, String> {
        let Action::Add(a, n) = *action;
        let a = self.actors.id(a);
        let expected = self.model.get(&a).copied().unwrap_or(0) + n;
        let got = CounterClient::new(env, &self.id).add(self.actors.get(a), &n);
        record_call(env);
        if got != expected {
            return Err(format!("add returned {got}, model expected {expected}"));
        }
        self.model.insert(a, expected);
        Ok(Outcome::Executed)
    }

    fn required_auths(&self, _env: &Env, action: &Action) -> Vec<Address> {
        let Action::Add(a, _) = *action;
        vec![self.actors.get(a).clone()]
    }
}

// In your crate, put this in a #[test] function.
fn main() {
    let report = Fuzzer::<CounterFuzz>::new()
        .cases(32)
        .check_unsigned_calls()
        .check();
    assert!(report.executed > 0);
}
```

For a larger example, see [`examples/vault`](https://github.com/soroban-dev-labs/Soroban-Fuzzer/tree/main/examples/vault). It is a token vault backed by a real Stellar Asset Contract, with a harness that checks token conservation, a compiled-Wasm variant, and five buggy variants (one per bug class) that the fuzzer must catch.

[`examples/stellar-asset`](https://github.com/soroban-dev-labs/Soroban-Fuzzer/tree/main/examples/stellar-asset) fuzzes production code: the **Stellar Asset Contract** built into the Soroban host. Its harness models transfers, allowances that expire, deauthorization and clawback, and the real contract matches the model across thousands of random sequences with time jumps.

## Writing a harness

| Method | Required | Purpose |
|---|---|---|
| `setup(env)` | yes | Register contracts, generate actors and build the initial model. Runs once per case on a fresh `Env`. |
| `actions()` | yes | A proptest strategy for one action. Refer to accounts by `ActorId`, not `Address`. |
| `apply(env, action)` | yes | Call the contract and update the model. Return `Executed`, `Rejected` (an expected contract error) or `Skipped`, or `Err` on a mismatch with the model. |
| `invariants(env)` | no | Properties that must hold after every step. |
| `required_auths(env, action)` | no | Who must sign the action. |
| `watched_contracts()` | no | Restrict the expiry scan to your own contracts. |

Helpers:

- **`check_call(env, name, client.try_x(..), expected)`** compares a `try_` call's result with the outcome your model expects, returns the right `Outcome`, records the call, and turns a trap into `UnexpectedPanic`.
- **`Outcome::if_executed(|| ..)`** runs a model update only when the call went through: `Ok(check_call(..)?.if_executed(|| model.debit(a, x)))`.
- **`expect_unless([(cond, Error::X), ..])`** builds the expected result from rules in the order the contract checks them.
- **`Balances`** is a per-actor amount model with `credit`, `debit`, `transfer`, `total` and `check(&actors, "what", |addr| contract.read(addr))`.
- **`ensure_eq!(contract_value, model_value, "what")`** returns an error showing both values when they differ.
- **`TestToken::deploy(env)`** deploys a Stellar Asset Contract. `mint_to_all(env, &actors, amount)` funds every actor and returns the matching `Balances`, and `check_balances` compares them with the contract.
- **`record_call(env)`** records a call made without `check_call`. The runner always records the *last* call of a step. Record earlier ones too, so that each call is checked against the resource budget and its signers are counted.
- **`relative_amount()` and `Amount::resolve(available)`** generate amounts relative to the state when the action runs (`All`, `Percent(n)`, `AllPlusOne`, `Exact(x)`). Plain random amounts rarely match a real balance, so most withdrawals end up rejected.
- **Other strategies:** `amount`, `amount_up_to`, `positive_amount`, `actor`, `ledger_jump`, `symbol_str` and `bytes` are biased toward edge values such as `0`, `±1` and `i128::MIN/MAX`, but shrink toward small, readable values.
- **`ttl::persistent/temporary/instance` and `storage::entries/expired`** read TTLs and expiry without side effects.

Tips:

- Keep view functions free of `extend_ttl`. Otherwise invariant checks that call them keep entries alive and hide lifecycle bugs.
- To add a regression test for a failing case, copy its minimal sequence into `Fuzzer::replay(vec![Step::Call(..), Step::AdvanceLedger(..)])`.

## Configuration

```rust,ignore
Fuzzer::<MyHarness>::new()
    .cases(500)                              // sequences to run (default 256)
    .steps(1..=64)                           // sequence length (default 1..=32)
    .seed(42)                                // fixed seed (default random)
    .ledger_jumps(LedgerJumps {
        weight: 2,                           // vs. 10 for an action
        max_jump: 50_000,                    // largest single jump
        horizon: 120_960,                    // state must stay live this long (≈7 days)
        seconds_per_ledger: 5,               // timestamp step per ledger jumped
    })
    .resource_budget(ResourceBudget::mainnet_percent(60))
    .check_unsigned_calls()                  // needs `MyHarness: Clone`
    .check();                                // panics with the report on failure
```

`run()` returns `Result<Report, Box<FuzzFailure<_>>>` if you want to inspect the result rather than panic. You can switch individual checks off with `check_auths(false)`, `check_ttl(false)`, `without_ledger_jumps()` and `mock_all_auths(false)`.

`horizon` is the TTL your contract promises. A case never advances the ledger further than this, so a contract that extends entries to at least `horizon` ledgers on access passes. One that relies on the network minimum TTL fails.

| Environment variable | Effect |
|---|---|
| `SOROBAN_FUZZ_CASES` | Number of cases, e.g. for a long nightly run. |
| `SOROBAN_FUZZ_SEED` | Replays a failure with the seed printed in its report. |

## Coverage-guided fuzzing with cargo-fuzz

```rust,ignore
// fuzz/fuzz_targets/my_contract.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_fuzzer::Fuzzer;

fuzz_target!(|data: &[u8]| Fuzzer::<MyHarness>::new().fuzz_one(data));
```

```bash
cargo +nightly fuzz run -s none my_contract -- -max_len=256 -len_control=0
```

The flags matter:
- `-s none` turns off AddressSanitizer, which safe Rust doesn't need. Runs are about 40 times faster without it.
- `-max_len=256 -len_control=0` lets libFuzzer try full-length sequences (32 steps) from the start. Otherwise it grows inputs slowly and spends its first minutes on one-step sequences.

Each 8 bytes of input become one step, generated by the same strategies the property-based mode uses. A one-byte mutation therefore changes exactly one step, and libFuzzer's coverage feedback gradually builds sequences that reach deep contract states. Failures panic with the usual report, and libFuzzer saves the input under `fuzz/artifacts/`.

## Measuring real costs

Contracts registered natively (`env.register(Contract, args)`) skip the Wasm VM, so their CPU and memory figures are lower than on chain. To measure real execution costs, register the compiled contract instead:

```rust,ignore
env.register(include_bytes!("../my_contract.wasm").as_slice(), args)
```

The vault example runs the same harness against both versions.

## Limitations

- The unsigned-call probe needs `mock_all_auths` (the default) and a `Clone` harness. A harness that calls `env.mock_all_auths()` itself inside `apply` defeats it.
- Resource limits are the mainnet snapshot shipped with `soroban-sdk` 29.
