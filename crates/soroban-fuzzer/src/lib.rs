#![doc = include_str!("../README.md")]

mod actors;
mod call;
mod env;
mod failure;
mod harness;
pub mod model;
mod panic;
mod report;
mod resources;
mod runner;
pub mod storage;
pub mod strategies;
pub mod ttl;

pub use actors::{ActorId, Actors};
pub use call::{check_call, record_call};
pub use env::{advance_ledgers, advance_ledgers_with, LedgerJumps, DEFAULT_SECONDS_PER_LEDGER};
pub use failure::{FailureKind, FuzzFailure};
pub use harness::{Harness, Outcome};
pub use model::{expect_unless, Balances, TestToken};
pub use panic::catch_quiet;
pub use report::Report;
pub use resources::{ResourceBudget, ResourceUsage};
pub use runner::{Fuzzer, Step};

/// Re-exported so harnesses don't need a direct dependency to write strategies.
pub use proptest;

/// Everything a typical harness needs in one import.
pub mod prelude {
    pub use crate::strategies::*;
    pub use crate::{
        advance_ledgers, check_call, ensure_eq, expect_unless, record_call, ActorId, Actors,
        Balances, FailureKind, FuzzFailure, Fuzzer, Harness, LedgerJumps, Outcome, Report,
        ResourceBudget, ResourceUsage, Step, TestToken,
    };
    pub use proptest::prelude::{any, prop_oneof, BoxedStrategy, Just, Strategy};
    pub use soroban_sdk::{testutils::Address as _, Address, Env};
}
