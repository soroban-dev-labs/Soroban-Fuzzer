use soroban_sdk::{
    testutils::{EnvTestConfig, Ledger},
    Env,
};

/// Default ledger close time, in seconds.
pub const DEFAULT_SECONDS_PER_LEDGER: u64 = 5;

/// Build the `Env` used for one fuzz case.
pub(crate) fn fresh_env(mock_all_auths: bool) -> Env {
    // Snapshots would write a JSON file per case; never wanted while fuzzing.
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    if mock_all_auths {
        env.mock_all_auths();
    }
    env
}

/// Move the ledger forward by `ledgers` (sequence number and timestamp),
/// assuming the default close time of
/// [`DEFAULT_SECONDS_PER_LEDGER`] seconds per ledger.
///
/// Storage entries whose TTL runs out become archived (persistent/instance)
/// or disappear (temporary), exactly as they would on the network.
pub fn advance_ledgers(env: &Env, ledgers: u32) {
    advance_ledgers_with(env, ledgers, DEFAULT_SECONDS_PER_LEDGER);
}

/// Like [`advance_ledgers`], but with an explicit close time: the timestamp
/// moves by `ledgers * seconds_per_ledger`.
pub fn advance_ledgers_with(env: &Env, ledgers: u32, seconds_per_ledger: u64) {
    env.ledger().with_mut(|l| {
        l.sequence_number = l.sequence_number.saturating_add(ledgers);
        l.timestamp = l
            .timestamp
            .saturating_add((ledgers as u64).saturating_mul(seconds_per_ledger));
    });
}

/// How the fuzzer interleaves ledger time jumps with actions.
///
/// Time jumps expose storage lifecycle bugs: data kept in `temporary()`
/// storage vanishes, and persistent entries that are never extended get
/// archived, which makes the next call touching them fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerJumps {
    /// Relative weight of a jump step against an action step (which has a
    /// weight of 10). `0` disables jumps.
    pub weight: u32,
    /// Largest single jump, in ledgers.
    pub max_jump: u32,
    /// Total ledgers a single case may advance. A contract is expected to
    /// keep all of its state alive for this long without anyone touching it,
    /// so set it to the TTL your contract promises (default ≈ 7 days).
    pub horizon: u32,
    /// Seconds the ledger timestamp moves per ledger jumped (default 5).
    /// Change it to test contracts that read `env.ledger().timestamp()`
    /// (vesting, auctions, timelocks) under a different close time.
    pub seconds_per_ledger: u64,
}

impl LedgerJumps {
    pub const DISABLED: Self = Self {
        weight: 0,
        max_jump: 0,
        horizon: 0,
        seconds_per_ledger: DEFAULT_SECONDS_PER_LEDGER,
    };

    pub fn enabled(&self) -> bool {
        self.weight > 0 && self.max_jump > 0 && self.horizon > 0
    }
}

impl Default for LedgerJumps {
    fn default() -> Self {
        Self {
            weight: 2,
            max_jump: 50_000,
            horizon: 120_960, // 7 days of 5s ledgers
            seconds_per_ledger: DEFAULT_SECONDS_PER_LEDGER,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jump(seconds_per_ledger: u64, ledgers: u32) -> (u32, u64) {
        let env = fresh_env(false);
        let (seq0, ts0) = (env.ledger().sequence(), env.ledger().timestamp());
        advance_ledgers_with(&env, ledgers, seconds_per_ledger);
        (
            env.ledger().sequence() - seq0,
            env.ledger().timestamp() - ts0,
        )
    }

    #[test]
    fn jump_moves_timestamp_by_n_times_seconds_per_ledger() {
        for (secs, n) in [(5, 100), (6, 1_000), (1, 7), (12, 0)] {
            assert_eq!(jump(secs, n), (n, n as u64 * secs));
        }
    }

    #[test]
    fn default_is_five_seconds() {
        assert_eq!(LedgerJumps::default().seconds_per_ledger, 5);
        let env = fresh_env(false);
        let ts0 = env.ledger().timestamp();
        advance_ledgers(&env, 10);
        assert_eq!(env.ledger().timestamp() - ts0, 50);
    }
}
