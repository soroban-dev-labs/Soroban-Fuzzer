//! The correct vault must survive fuzzing with every check enabled.

use std::vec;

use soroban_fuzzer::prelude::*;

use crate::{
    harness::{Action, VaultHarness},
    Vault,
};

type H = VaultHarness<Vault>;

#[test]
fn passes_with_every_check() {
    let report = Fuzzer::<H>::new().cases(128).check_unsigned_calls().check();
    assert!(
        report.ledger_jumps > 0,
        "no ledger jump was generated: {report}"
    );
    assert!(
        report.peak.instructions > 0,
        "resources were not metered: {report}"
    );
    // Relative amounts keep most generated calls meaningful.
    assert!(
        report.executed > report.rejected,
        "most calls should execute, not be rejected: {report}"
    );
}

#[test]
fn fixed_seed_is_deterministic() {
    let run = || Fuzzer::<H>::new().cases(16).seed(7).run().unwrap();
    let (a, b) = (run(), run());
    assert_eq!(
        (a.steps, a.executed, a.rejected, a.ledger_jumps, a.peak),
        (b.steps, b.executed, b.rejected, b.ledger_jumps, b.peak)
    );
}

#[test]
fn replay_runs_an_explicit_sequence() {
    let steps = vec![
        Step::Call(Action::Deposit(ActorId(0), Amount::Exact(100))),
        Step::AdvanceLedger(100_000),
        Step::Call(Action::Transfer(
            ActorId(0),
            ActorId(1),
            Amount::Percent(40),
        )),
        Step::Call(Action::Withdraw(ActorId(1), Amount::All)),
        Step::Call(Action::Withdraw(ActorId(0), Amount::AllPlusOne)), // rejected
        Step::Call(Action::Deposit(ActorId(2), Amount::All)),
        Step::Call(Action::Deposit(ActorId(3), Amount::Exact(i128::MAX))), // rejected
    ];
    Fuzzer::<H>::new()
        .check_unsigned_calls()
        .replay(steps)
        .unwrap();
}

#[test]
fn tight_budget_is_reported() {
    let err = Fuzzer::<H>::new()
        .cases(32)
        .resource_budget(ResourceBudget {
            max_instructions: 1_000,
            ..ResourceBudget::UNLIMITED
        })
        .run()
        .unwrap_err();
    assert_eq!(err.kind, FailureKind::ResourceBudgetExceeded, "{err}");
    assert_eq!(err.steps.len(), 1, "should shrink to a single call: {err}");
}

#[test]
fn horizon_longer_than_ttl_is_reported() {
    // The vault promises 30 days; asking for 60 must fail on the TTL check.
    let err = Fuzzer::<H>::new()
        .seed(3)
        .ledger_jumps(LedgerJumps {
            weight: 5,
            max_jump: 600_000,
            horizon: 60 * 17_280,
            ..LedgerJumps::default()
        })
        .run()
        .unwrap_err();
    assert_eq!(err.kind, FailureKind::ArchivedEntry, "{err}");
}
