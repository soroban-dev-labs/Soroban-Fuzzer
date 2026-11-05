//! The harness: a model of the Stellar Asset Contract's rules for contract
//! (`C…`) address holders, checked against the real contract.
//!
//! The rules come from the host's implementation (`soroban-env-host`,
//! `builtin_contracts/stellar_asset_contract`), including the order in which
//! checks run, because the order decides which error a call returns.

use std::collections::BTreeMap;

use soroban_fuzzer::prelude::*;
use soroban_sdk::{testutils::IssuerFlags, Error};

/// Number of token holders.
pub const ACTORS: u8 = 4;
/// Tokens minted to each holder at the start of every case.
pub const INITIAL: i128 = 1_000_000_000;

/// The SAC's contract error codes (`ContractError` in the host).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SacError {
    NegativeAmount = 8,
    Allowance = 9,
    Balance = 10,
    BalanceDeauthorized = 11,
    Overflow = 12,
}

impl From<SacError> for Error {
    fn from(e: SacError) -> Self {
        Error::from_contract_error(e as u32)
    }
}

/// When an allowance expires, relative to the ledger the call runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// The current ledger: valid for this ledger only.
    Now,
    /// This many ledgers from now.
    In(u32),
    /// The ledger before the current one: only valid to clear an allowance.
    Past,
    /// The furthest ledger the network allows.
    Max,
    /// One past the furthest allowed ledger: always rejected.
    BeyondMax,
}

#[derive(Clone, Debug)]
pub enum Action {
    Transfer(ActorId, ActorId, Amount),
    Approve(ActorId, ActorId, Amount, Expiry),
    TransferFrom(ActorId, ActorId, ActorId, Amount),
    Burn(ActorId, Amount),
    BurnFrom(ActorId, ActorId, Amount),
    Mint(ActorId, Amount),
    Clawback(ActorId, Amount),
    SetAuthorized(ActorId, bool),
    SetAdmin(ActorId),
}

/// An allowance as the SAC stores it.
#[derive(Clone, Copy, Debug, Default)]
struct Allowance {
    amount: i128,
    live_until: u32,
}

#[derive(Clone)]
pub struct SacHarness {
    pub token: TestToken,
    pub actors: Actors,
    admin: ActorId,
    balances: Balances,
    deauthorized: Vec<ActorId>,
    /// Keyed by (from, spender).
    allowances: BTreeMap<(ActorId, ActorId), Allowance>,
}

impl SacHarness {
    fn allowance(&self, env: &Env, from: ActorId, spender: ActorId) -> i128 {
        match self.allowances.get(&(from, spender)) {
            Some(a) if a.live_until >= env.ledger().sequence() => a.amount,
            _ => 0,
        }
    }

    fn authorized(&self, a: ActorId) -> bool {
        !self.deauthorized.contains(&a)
    }

    /// The error `spend_balance` raises, if any.
    fn spend_error(&self, a: ActorId, x: i128) -> Option<SacError> {
        if !self.authorized(a) {
            Some(SacError::BalanceDeauthorized)
        } else if self.balances.get(a) < x {
            Some(SacError::Balance)
        } else {
            None
        }
    }

    /// The error `receive_balance` raises, if any. `before` is the
    /// receiver's balance when it receives (a self-transfer has already
    /// spent from it).
    fn receive_error(&self, a: ActorId, x: i128, before: i128) -> Option<SacError> {
        if !self.authorized(a) {
            Some(SacError::BalanceDeauthorized)
        } else if before.checked_add(x).is_none() {
            Some(SacError::Overflow)
        } else {
            None
        }
    }

    /// Errors for moving `x` from `a` to `b`, in the order the SAC checks.
    fn move_error(&self, a: ActorId, b: ActorId, x: i128) -> Option<SacError> {
        let b_before = self.balances.get(b) - if a == b { x } else { 0 };
        self.spend_error(a, x)
            .or_else(|| self.receive_error(b, x, b_before))
    }

    fn spend_allowance(&mut self, from: ActorId, spender: ActorId, x: i128) {
        if x > 0 {
            if let Some(a) = self.allowances.get_mut(&(from, spender)) {
                a.amount -= x;
            }
        }
    }
}

fn expected(err: Option<SacError>) -> Result<(), Error> {
    err.map_or(Ok(()), |e| Err(e.into()))
}

fn amount_and(n: u8) -> impl Strategy<Value = (ActorId, Amount)> {
    (actor(n), relative_amount())
}

impl Harness for SacHarness {
    type Action = Action;

    fn setup(env: &Env) -> Self {
        let actors = Actors::generate(env, ACTORS as usize);
        let admin = ActorId(0);
        let sac = env.register_stellar_asset_contract_v2(actors.get(admin).clone());
        // Allow deauthorization and clawback. New balances pick up the
        // clawback flag when created, so set it before minting.
        sac.issuer().set_flag(IssuerFlags::RevocableFlag);
        sac.issuer().set_flag(IssuerFlags::ClawbackEnabledFlag);
        let token = TestToken::from_sac(sac, actors.get(admin).clone());
        Self {
            balances: token.mint_to_all(env, &actors, INITIAL),
            token,
            actors,
            admin,
            deauthorized: Vec::new(),
            allowances: BTreeMap::new(),
        }
    }

    fn actions() -> BoxedStrategy<Action> {
        let n = ACTORS;
        let expiry = prop_oneof![
            4 => (0u32..200_000).prop_map(Expiry::In),
            1 => Just(Expiry::Now),
            1 => Just(Expiry::Past),
            1 => Just(Expiry::Max),
            1 => Just(Expiry::BeyondMax),
        ];
        prop_oneof![
            4 => (actor(n), amount_and(n)).prop_map(|(a, (b, x))| Action::Transfer(a, b, x)),
            3 => (actor(n), amount_and(n), expiry)
                .prop_map(|(a, (s, x), e)| Action::Approve(a, s, x, e)),
            4 => (actor(n), actor(n), amount_and(n))
                .prop_map(|(s, a, (b, x))| Action::TransferFrom(s, a, b, x)),
            1 => amount_and(n).prop_map(|(a, x)| Action::Burn(a, x)),
            2 => (actor(n), amount_and(n)).prop_map(|(s, (a, x))| Action::BurnFrom(s, a, x)),
            1 => amount_and(n).prop_map(|(a, x)| Action::Mint(a, x)),
            1 => amount_and(n).prop_map(|(a, x)| Action::Clawback(a, x)),
            1 => (actor(n), any::<bool>()).prop_map(|(a, on)| Action::SetAuthorized(a, on)),
            1 => actor(n).prop_map(Action::SetAdmin),
        ]
        .boxed()
    }

    fn apply(&mut self, env: &Env, action: &Action) -> Result<Outcome, String> {
        let token = self.token.client(env);
        let admin = self.token.admin_client(env);
        let id = |a| self.actors.id(a);
        let addr = |a| self.actors.get(a).clone();
        let negative = |x: i128| (x < 0).then_some(SacError::NegativeAmount);
        match *action {
            Action::Transfer(a, b, x) => {
                let (a, b) = (id(a), id(b));
                let x = x.resolve(self.balances.get(a));
                let err = negative(x).or_else(|| self.move_error(a, b, x));
                let got = token.try_transfer(&addr(a), addr(b), &x);
                Ok(check_call(env, "transfer", got, expected(err))?
                    .if_executed(|| self.balances.transfer(a, b, x)))
            }
            Action::Approve(a, s, x, expiry) => {
                let (a, s) = (id(a), id(s));
                let x = x.resolve(self.balances.get(a));
                let seq = env.ledger().sequence();
                let max = seq + env.storage().max_ttl();
                let live_until = match expiry {
                    Expiry::Now => seq,
                    Expiry::In(n) => seq.saturating_add(n).min(max),
                    Expiry::Past => seq.saturating_sub(1),
                    Expiry::Max => max,
                    Expiry::BeyondMax => max + 1,
                };
                let err = negative(x).or_else(|| {
                    (live_until > max || (x > 0 && live_until < seq)).then_some(SacError::Allowance)
                });
                let got = token.try_approve(&addr(a), &addr(s), &x, &live_until);
                Ok(
                    check_call(env, "approve", got, expected(err))?.if_executed(|| {
                        self.allowances.insert(
                            (a, s),
                            Allowance {
                                amount: x,
                                live_until,
                            },
                        );
                    }),
                )
            }
            Action::TransferFrom(s, a, b, x) => {
                let (s, a, b) = (id(s), id(a), id(b));
                let allowed = self.allowance(env, a, s);
                let x = x.resolve(allowed);
                let err = negative(x)
                    .or_else(|| (allowed < x).then_some(SacError::Allowance))
                    .or_else(|| self.move_error(a, b, x));
                let got = token.try_transfer_from(&addr(s), &addr(a), &addr(b), &x);
                Ok(
                    check_call(env, "transfer_from", got, expected(err))?.if_executed(|| {
                        self.spend_allowance(a, s, x);
                        self.balances.transfer(a, b, x);
                    }),
                )
            }
            Action::Burn(a, x) => {
                let a = id(a);
                let x = x.resolve(self.balances.get(a));
                let err = negative(x).or_else(|| self.spend_error(a, x));
                let got = token.try_burn(&addr(a), &x);
                Ok(check_call(env, "burn", got, expected(err))?
                    .if_executed(|| self.balances.debit(a, x)))
            }
            Action::BurnFrom(s, a, x) => {
                let (s, a) = (id(s), id(a));
                let allowed = self.allowance(env, a, s);
                let x = x.resolve(allowed);
                let err = negative(x)
                    .or_else(|| (allowed < x).then_some(SacError::Allowance))
                    .or_else(|| self.spend_error(a, x));
                let got = token.try_burn_from(&addr(s), &addr(a), &x);
                Ok(
                    check_call(env, "burn_from", got, expected(err))?.if_executed(|| {
                        self.spend_allowance(a, s, x);
                        self.balances.debit(a, x);
                    }),
                )
            }
            Action::Mint(a, x) => {
                let a = id(a);
                let x = x.resolve(self.balances.get(a));
                let err = negative(x).or_else(|| self.receive_error(a, x, self.balances.get(a)));
                let got = admin.try_mint(&addr(a), &x);
                Ok(check_call(env, "mint", got, expected(err))?
                    .if_executed(|| self.balances.credit(a, x)))
            }
            Action::Clawback(a, x) => {
                // Clawback ignores deauthorization; it only needs the funds.
                let a = id(a);
                let x = x.resolve(self.balances.get(a));
                let err =
                    negative(x).or_else(|| (self.balances.get(a) < x).then_some(SacError::Balance));
                let got = admin.try_clawback(&addr(a), &x);
                Ok(check_call(env, "clawback", got, expected(err))?
                    .if_executed(|| self.balances.debit(a, x)))
            }
            Action::SetAuthorized(a, on) => {
                let a = id(a);
                let got = admin.try_set_authorized(&addr(a), &on);
                Ok(
                    check_call(env, "set_authorized", got, Ok::<(), Error>(()))?.if_executed(
                        || {
                            self.deauthorized.retain(|d| *d != a);
                            if !on {
                                self.deauthorized.push(a);
                            }
                        },
                    ),
                )
            }
            Action::SetAdmin(a) => {
                let a = id(a);
                let got = admin.try_set_admin(&addr(a));
                Ok(check_call(env, "set_admin", got, Ok::<(), Error>(()))?
                    .if_executed(|| self.admin = a))
            }
        }
    }

    // Note: the SAC extends TTLs whenever it is read, so these reads keep its
    // entries alive. Its own TTLs (7 days for the instance, 30 for balances)
    // already cover the default 7-day horizon, so nothing is hidden here.
    fn invariants(&self, env: &Env) -> Result<(), String> {
        let token = self.token.client(env);
        let admin = self.token.admin_client(env);
        ensure_eq!(
            admin.admin(),
            self.actors.get(self.admin).clone(),
            "admin"
        );
        self.token
            .check_balances(env, &self.actors, &self.balances)?;
        for (a, from) in self.actors.iter() {
            ensure_eq!(
                admin.authorized(from),
                self.authorized(a),
                "authorized({})",
                a.0
            );
            for (s, spender) in self.actors.iter() {
                ensure_eq!(
                    token.allowance(from, spender),
                    self.allowance(env, a, s),
                    "allowance({} -> {})",
                    a.0,
                    s.0
                );
            }
        }
        Ok(())
    }

    fn required_auths(&self, _env: &Env, action: &Action) -> Vec<Address> {
        let signer = match *action {
            Action::Transfer(a, ..) | Action::Approve(a, ..) | Action::Burn(a, _) => {
                self.actors.get(a).clone()
            }
            Action::TransferFrom(s, ..) | Action::BurnFrom(s, ..) => self.actors.get(s).clone(),
            Action::Mint(..)
            | Action::Clawback(..)
            | Action::SetAuthorized(..)
            | Action::SetAdmin(..) => self.actors.get(self.admin).clone(),
        };
        vec![signer]
    }
}
