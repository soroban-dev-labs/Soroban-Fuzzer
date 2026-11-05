use std::{cell::RefCell, fmt, marker::PhantomData, ops::RangeInclusive};

use proptest::{
    collection::vec,
    strategy::{BoxedStrategy, Strategy, Union, ValueTree},
    test_runner::{Config, RngAlgorithm, TestCaseError, TestError, TestRng, TestRunner},
};
use soroban_sdk::Env;

use crate::{
    call,
    env::{advance_ledgers_with, fresh_env},
    failure::{FailureKind, FuzzFailure},
    harness::{Harness, Outcome},
    panic::catch_quiet,
    report::Report,
    resources::{ResourceBudget, ResourceUsage},
    storage,
    strategies::ledger_jump,
    LedgerJumps,
};

/// One element of a generated test case.
#[derive(Clone, PartialEq, Eq)]
pub enum Step<A> {
    /// Apply a harness action.
    Call(A),
    /// Advance the ledger by this many ledgers.
    AdvanceLedger(u32),
}

impl<A: fmt::Debug> fmt::Debug for Step<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Call(a) => a.fmt(f),
            Step::AdvanceLedger(n) => write!(f, "<advance {n} ledgers>"),
        }
    }
}

/// Configures and runs a fuzzing campaign for a [`Harness`].
///
/// Environment variables override the code configuration so CI can run
/// longer campaigns and failures can be replayed:
///
/// - `SOROBAN_FUZZ_CASES` — number of cases.
/// - `SOROBAN_FUZZ_SEED` — fixed seed (printed with every failure).
pub struct Fuzzer<H: Harness> {
    cases: u32,
    steps: RangeInclusive<usize>,
    seed: Option<u64>,
    jumps: LedgerJumps,
    budget: ResourceBudget,
    mock_all_auths: bool,
    check_auths: bool,
    check_ttl: bool,
    unsigned_probe: Option<fn(&H) -> H>,
    max_shrink_iters: u32,
    _harness: PhantomData<fn() -> H>,
}

impl<H: Harness> Default for Fuzzer<H> {
    fn default() -> Self {
        Self::new()
    }
}

struct CaseFailure {
    kind: FailureKind,
    message: String,
    step: Option<usize>,
}

impl<H: Harness> Fuzzer<H> {
    pub fn new() -> Self {
        Self {
            cases: 256,
            steps: 1..=32,
            seed: None,
            jumps: LedgerJumps::default(),
            budget: ResourceBudget::default(),
            mock_all_auths: true,
            check_auths: true,
            check_ttl: true,
            unsigned_probe: None,
            max_shrink_iters: 4096,
            _harness: PhantomData,
        }
    }

    /// Number of random cases (sequences) to run. Default 256.
    pub fn cases(mut self, cases: u32) -> Self {
        self.cases = cases;
        self
    }

    /// Range of sequence lengths. Default `1..=32`.
    pub fn steps(mut self, steps: RangeInclusive<usize>) -> Self {
        assert!(!steps.is_empty(), "step range must not be empty");
        self.steps = steps;
        self
    }

    /// Use a fixed seed (default: random, or `SOROBAN_FUZZ_SEED`).
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Configure ledger time jumps.
    pub fn ledger_jumps(mut self, jumps: LedgerJumps) -> Self {
        self.jumps = jumps;
        self
    }

    /// Never advance the ledger.
    pub fn without_ledger_jumps(self) -> Self {
        self.ledger_jumps(LedgerJumps::DISABLED)
    }

    /// Per-invocation resource budget. Default: 75% of mainnet limits.
    pub fn resource_budget(mut self, budget: ResourceBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Whether to call `env.mock_all_auths()` on every fresh `Env`
    /// (default `true`). Turn off if the harness manages auth itself.
    pub fn mock_all_auths(mut self, on: bool) -> Self {
        self.mock_all_auths = on;
        self
    }

    /// Whether to check [`Harness::required_auths`] (default `true`).
    pub fn check_auths(mut self, on: bool) -> Self {
        self.check_auths = on;
        self
    }

    /// Whether to fail when a watched persistent or instance entry expires
    /// (default `true`). See [`Harness::watched_contracts`].
    pub fn check_ttl(mut self, on: bool) -> Self {
        self.check_ttl = on;
        self
    }

    /// Also replay every signed action **with no signatures at all** and fail
    /// with [`FailureKind::AuthBypass`] if it still changes the ledger.
    ///
    /// This complements the `required_auths` check, which only looks at the
    /// auths the host *recorded*: the probe uses real auth enforcement, so it
    /// also catches auth that is recorded but not actually enforced. It runs
    /// on a clone of the harness before each signed action, and needs
    /// `mock_all_auths` to be on (the default).
    pub fn check_unsigned_calls(mut self) -> Self
    where
        H: Clone,
    {
        self.unsigned_probe = Some(H::clone);
        self
    }

    /// Upper bound on shrinking iterations. Default 4096.
    pub fn max_shrink_iters(mut self, iters: u32) -> Self {
        self.max_shrink_iters = iters;
        self
    }

    /// Run the campaign and panic with a readable report on failure.
    /// Intended to be called from a `#[test]`.
    pub fn check(self) -> Report {
        match self.run() {
            Ok(report) => {
                println!("{report}");
                report
            }
            Err(failure) => panic!("\n{failure}\n"),
        }
    }

    /// Run the campaign. Returns the shrunk failing case, if any.
    pub fn run(&self) -> Result<Report, Box<FuzzFailure<H::Action>>> {
        let seed = self.resolve_seed();
        let cases = env_u32("SOROBAN_FUZZ_CASES").unwrap_or(self.cases);
        let config = Config {
            cases,
            max_shrink_iters: self.max_shrink_iters,
            failure_persistence: None,
            ..Config::default()
        };
        let mut runner = TestRunner::new_with_rng(
            config,
            TestRng::from_seed(RngAlgorithm::ChaCha, &seed_bytes(seed)),
        );

        let report = RefCell::new(Report {
            seed,
            cases,
            ..Report::default()
        });
        let strategy = self.strategy();
        let result = runner.run(&strategy, |steps| {
            let mut r = report.borrow_mut();
            self.execute(&steps, &mut r)
                .map_err(|f| TestCaseError::fail(format!("{:?}: {}", f.kind, f.message)))
        });

        match result {
            Ok(()) => Ok(report.into_inner()),
            Err(TestError::Fail(reason, steps)) => {
                // Replay the minimal case to recover the structured failure.
                let failure = self
                    .execute(&steps, &mut Report::default())
                    .err()
                    .unwrap_or(CaseFailure {
                        kind: FailureKind::UnexpectedPanic,
                        message: format!("non-deterministic failure (did not replay): {reason}"),
                        step: None,
                    });
                Err(Box::new(FuzzFailure {
                    kind: failure.kind,
                    message: failure.message,
                    step: failure.step,
                    steps,
                    seed,
                }))
            }
            Err(TestError::Abort(reason)) => panic!("soroban-fuzzer aborted: {reason}"),
        }
    }

    /// Run one case whose steps are decoded from raw fuzzer input, for use
    /// in a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target:
    ///
    /// ```ignore
    /// fuzz_target!(|data: &[u8]| Fuzzer::<MyHarness>::new().fuzz_one(data));
    /// ```
    ///
    /// Every 8 bytes of input become one step, generated by the same
    /// strategies [`Fuzzer::run`] uses. A one-byte mutation therefore changes
    /// one step, which lets libFuzzer's coverage feedback build up sequences
    /// that reach deeper contract states. All the usual checks run. When one
    /// fails, this panics with the failure report, which libFuzzer records
    /// as a crash.
    ///
    /// Run with `cargo fuzz run -s none <target> -- -max_len=256 -len_control=0`:
    /// safe Rust needs no sanitizer, and a fixed input length lets libFuzzer
    /// try full-length sequences from the start.
    pub fn fuzz_one(&self, data: &[u8]) {
        let steps = self.decode(data);
        if let Err(f) = self.execute(&steps, &mut Report::default()) {
            let failure = FuzzFailure {
                kind: f.kind,
                message: f.message,
                step: f.step,
                steps,
                seed: 0,
            };
            panic!("\n{failure}\n");
        }
    }

    /// Turn fuzzer input into steps: every 8-byte chunk seeds the generator
    /// of one step, so a mutation of one byte changes exactly one step and
    /// inserting or removing chunks adds or removes steps.
    fn decode(&self, data: &[u8]) -> Vec<Step<H::Action>> {
        const CHUNK: usize = 8;
        let strategy = self.step_strategy();
        let n = data
            .len()
            .div_ceil(CHUNK)
            .clamp(*self.steps.start(), *self.steps.end());
        (0..n)
            .filter_map(|i| {
                let mut chunk = [0u8; CHUNK];
                let bytes = data.get(i * CHUNK..).unwrap_or_default();
                let len = bytes.len().min(CHUNK);
                chunk[..len].copy_from_slice(&bytes[..len]);
                let seed = u64::from_le_bytes(chunk) ^ (i as u64).rotate_left(32);
                let mut runner = TestRunner::new_with_rng(
                    Config::default(),
                    TestRng::from_seed(RngAlgorithm::ChaCha, &seed_bytes(seed)),
                );
                strategy.new_tree(&mut runner).ok().map(|t| t.current())
            })
            .collect()
    }

    /// Run one explicit sequence of steps (e.g. a regression case).
    pub fn replay(&self, steps: Vec<Step<H::Action>>) -> Result<(), Box<FuzzFailure<H::Action>>> {
        self.execute(&steps, &mut Report::default()).map_err(|f| {
            Box::new(FuzzFailure {
                kind: f.kind,
                message: f.message,
                step: f.step,
                steps,
                seed: 0,
            })
        })
    }

    fn resolve_seed(&self) -> u64 {
        if let Some(s) = std::env::var("SOROBAN_FUZZ_SEED")
            .ok()
            .and_then(|v| v.trim().parse().ok())
        {
            return s;
        }
        self.seed.unwrap_or_else(random_seed)
    }

    fn step_strategy(&self) -> BoxedStrategy<Step<H::Action>> {
        let calls = H::actions().prop_map(Step::Call).boxed();
        if self.jumps.enabled() {
            let jumps = ledger_jump(self.jumps.max_jump)
                .prop_map(Step::AdvanceLedger)
                .boxed();
            Union::new_weighted(vec![(10, calls), (self.jumps.weight, jumps)]).boxed()
        } else {
            calls
        }
    }

    fn strategy(&self) -> BoxedStrategy<Vec<Step<H::Action>>> {
        vec(self.step_strategy(), self.steps.clone()).boxed()
    }

    fn execute(&self, steps: &[Step<H::Action>], report: &mut Report) -> Result<(), CaseFailure> {
        let fail = |kind, message, step| {
            Err(CaseFailure {
                kind,
                message,
                step,
            })
        };

        let env = fresh_env(self.mock_all_auths);
        let mut harness = match catch_quiet(|| H::setup(&env)) {
            Ok(h) => h,
            Err(msg) => return fail(FailureKind::Setup, msg, None),
        };
        self.check_invariants(&env, &harness, None)?;

        let mut advanced: u32 = 0;
        let mut last_scan = env.ledger().sequence();
        for (i, step) in steps.iter().enumerate() {
            report.steps += 1;
            match step {
                Step::AdvanceLedger(n) => {
                    let n = (*n).min(self.jumps.horizon.saturating_sub(advanced));
                    if n > 0 {
                        advance_ledgers_with(&env, n, self.jumps.seconds_per_ledger);
                        advanced += n;
                        report.ledger_jumps += 1;
                    }
                }
                Step::Call(action) => {
                    let required = if self.check_auths || self.unsigned_probe.is_some() {
                        catch_quiet(|| harness.required_auths(&env, action)).unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    if let Some(clone) = self.unsigned_probe {
                        if self.mock_all_auths && !required.is_empty() {
                            self.probe_unsigned(&env, clone(&harness), action, i)?;
                        }
                    }
                    call::start_recording();
                    let applied = catch_quiet(|| harness.apply(&env, action));
                    let mut record = call::finish_recording();
                    let outcome = match applied {
                        Ok(Ok(o)) => o,
                        Ok(Err(msg)) => return fail(FailureKind::ModelMismatch, msg, Some(i)),
                        Err(msg) => return fail(FailureKind::from_panic(&msg), msg, Some(i)),
                    };
                    match outcome {
                        Outcome::Executed => report.executed += 1,
                        Outcome::Rejected => report.rejected += 1,
                        Outcome::Skipped => report.skipped += 1,
                    }
                    if outcome != Outcome::Skipped {
                        // The last call is always observed, even when the
                        // harness did not record it itself.
                        if let Some(u) = ResourceUsage::last(&env) {
                            record.usages.push(u);
                        }
                        record
                            .signers
                            .extend(env.auths().into_iter().map(|(a, _)| a));
                        for usage in &record.usages {
                            report.peak = report.peak.max(*usage);
                            if let Some(over) = self.budget.check(usage) {
                                return fail(
                                    FailureKind::ResourceBudgetExceeded,
                                    format!("{over}\n  usage: {usage}"),
                                    Some(i),
                                );
                            }
                        }
                    }
                    if self.check_auths && outcome == Outcome::Executed {
                        for addr in &required {
                            if !record.signers.contains(addr) {
                                return fail(
                                    FailureKind::MissingAuth,
                                    format!(
                                        "{addr:?} must authorise {action:?} but did not; \
                                         recorded signers: {:?}",
                                        record.signers
                                    ),
                                    Some(i),
                                );
                            }
                        }
                    }
                }
            }
            // Entries can only expire when the ledger moves (a jump, or the
            // harness advancing it), so only rescan then. This runs before the
            // invariants, whose reads would otherwise silently restore entries.
            if self.check_ttl && env.ledger().sequence() != last_scan {
                last_scan = env.ledger().sequence();
                self.check_expired(&env, &harness, i)?;
            }
            self.check_invariants(&env, &harness, Some(i))?;
        }
        Ok(())
    }

    /// Apply `action` on a throwaway harness clone with auth enforcement on
    /// and no signatures. A correct contract fails the call, and the host
    /// rolls every change back; any ledger difference means the call went
    /// through unsigned.
    fn probe_unsigned(
        &self,
        env: &Env,
        mut probe: H,
        action: &H::Action,
        step: usize,
    ) -> Result<(), CaseFailure> {
        let before = storage::snapshot(env);
        let saved = call::pause_recording();
        env.set_auths(&[]);
        let _ = catch_quiet(|| probe.apply(env, action));
        env.mock_all_auths();
        call::resume_recording(saved);
        let changed = storage::changed_entries(&before, &storage::snapshot(env));
        if changed.is_empty() {
            return Ok(());
        }
        Err(CaseFailure {
            kind: FailureKind::AuthBypass,
            message: format!(
                "{action:?} changed {} ledger entr{} with no signatures:\n{}",
                changed.len(),
                if changed.len() == 1 { "y" } else { "ies" },
                changed
                    .iter()
                    .map(|e| format!("    {e}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            step: Some(step),
        })
    }

    fn check_expired(&self, env: &Env, h: &H, step: usize) -> Result<(), CaseFailure> {
        let watched = catch_quiet(|| h.watched_contracts()).unwrap_or(None);
        let expired = storage::expired(env, watched.as_deref());
        if expired.is_empty() {
            return Ok(());
        }
        let list: Vec<String> = expired.iter().map(|e| format!("    {e:?}")).collect();
        Err(CaseFailure {
            kind: FailureKind::ArchivedEntry,
            message: format!(
                "{} entr{} expired at ledger {}:\n{}",
                expired.len(),
                if expired.len() == 1 { "y" } else { "ies" },
                env.ledger().sequence(),
                list.join("\n")
            ),
            step: Some(step),
        })
    }

    fn check_invariants(&self, env: &Env, h: &H, step: Option<usize>) -> Result<(), CaseFailure> {
        let (kind, message) = match catch_quiet(|| h.invariants(env)) {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(msg)) => (FailureKind::InvariantViolated, msg),
            Err(msg) => match FailureKind::from_panic(&msg) {
                FailureKind::UnexpectedPanic => (FailureKind::InvariantViolated, msg),
                kind => (kind, msg),
            },
        };
        Err(CaseFailure {
            kind,
            message,
            step,
        })
    }
}

fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

fn random_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    h.finish()
}

/// Expand a u64 seed into the 32 bytes ChaCha needs (splitmix64).
fn seed_bytes(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut x = seed;
    for chunk in out.chunks_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_expansion_is_deterministic_and_distinct() {
        assert_eq!(seed_bytes(1), seed_bytes(1));
        assert_ne!(seed_bytes(1), seed_bytes(2));
        assert_ne!(seed_bytes(0), [0; 32]);
    }

    #[test]
    fn steps_debug_format() {
        assert_eq!(format!("{:?}", Step::Call(3)), "3");
        assert_eq!(
            format!("{:?}", Step::<u8>::AdvanceLedger(7)),
            "<advance 7 ledgers>"
        );
    }
}
