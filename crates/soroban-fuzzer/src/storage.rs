//! Side-effect free view of the ledger entries held by the test `Env`.
//!
//! Reading storage through `env.storage()` (or the SDK's `get_ttl`) touches
//! the entry, and since protocol 23 touching an archived entry silently
//! *restores* it. To observe expiry without changing it, the fuzzer reads the
//! host's raw storage map instead.

use std::fmt;

use soroban_sdk::{
    xdr::{ContractDataDurability, LedgerEntry, LedgerKey, ScAddress, ScVal},
    Address, Env, TryFromVal,
};

/// Storage class of a contract ledger entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    Persistent,
    Temporary,
    /// The contract instance entry (holds instance storage).
    Instance,
    /// Contract code (Wasm). Native test contracts have one too.
    Code,
}

/// One contract-related entry in the test ledger.
#[derive(Clone)]
pub struct StoredEntry {
    /// Owning contract (`None` for code entries).
    pub contract: Option<ScAddress>,
    /// Storage key (`None` for code entries).
    pub key: Option<ScVal>,
    pub durability: Durability,
    /// Last ledger (inclusive) on which the entry is live.
    pub live_until: u32,
}

impl StoredEntry {
    /// `true` once the entry's TTL has run out at ledger `seq`.
    pub fn is_expired(&self, seq: u32) -> bool {
        self.live_until < seq
    }

    /// Ledgers left to live at `seq` (`0` when expired).
    pub fn ttl(&self, seq: u32) -> u32 {
        self.live_until.saturating_sub(seq)
    }

    pub fn belongs_to(&self, contract: &Address) -> bool {
        self.contract.as_ref() == Some(&ScAddress::from(contract))
    }
}

impl fmt::Debug for StoredEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} entry", self.durability)?;
        if let Some(c) = &self.contract {
            write!(f, " of {c}")?;
        }
        if let Some(k) = &self.key {
            if self.durability != Durability::Instance {
                write!(f, " key={}", short_scval(k))?;
            }
        }
        write!(f, " (live until ledger {})", self.live_until)
    }
}

/// All contract data and code entries currently in the ledger.
pub fn entries(env: &Env) -> Vec<StoredEntry> {
    let stored = env
        .host()
        .get_stored_entries()
        .expect("reading test ledger storage");
    stored
        .iter()
        .filter_map(|(key, value)| {
            let live_until = value.as_ref().and_then(|(_, ttl)| *ttl)?;
            match key.as_ref() {
                LedgerKey::ContractData(d) => {
                    let durability = match (&d.key, d.durability) {
                        (ScVal::LedgerKeyContractInstance, _) => Durability::Instance,
                        (_, ContractDataDurability::Persistent) => Durability::Persistent,
                        (_, ContractDataDurability::Temporary) => Durability::Temporary,
                    };
                    Some(StoredEntry {
                        contract: Some(d.contract.clone()),
                        key: Some(d.key.clone()),
                        durability,
                        live_until,
                    })
                }
                LedgerKey::ContractCode(_) => Some(StoredEntry {
                    contract: None,
                    key: None,
                    durability: Durability::Code,
                    live_until,
                }),
                _ => None,
            }
        })
        .collect()
}

/// Archivable entries (persistent, instance, code) whose TTL has run out.
///
/// When `contracts` is `Some`, only data entries of those contracts are
/// considered (code entries are skipped as they are shared).
pub fn expired(env: &Env, contracts: Option<&[Address]>) -> Vec<StoredEntry> {
    let seq = env.ledger().sequence();
    entries(env)
        .into_iter()
        .filter(|e| e.durability != Durability::Temporary && e.is_expired(seq))
        .filter(|e| match contracts {
            None => true,
            Some(cs) => cs.iter().any(|c| e.belongs_to(c)),
        })
        .collect()
}

/// Find the entry for `key` of `contract` with the given durability.
pub(crate) fn find(
    env: &Env,
    contract: &Address,
    key: Option<&ScVal>,
    durability: Durability,
) -> Option<StoredEntry> {
    entries(env).into_iter().find(|e| {
        e.durability == durability
            && e.belongs_to(contract)
            && (key.is_none() || e.key.as_ref() == key)
    })
}

/// Convert any contract value into its XDR form for key comparisons.
pub(crate) fn to_scval<K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(
    env: &Env,
    key: &K,
) -> ScVal {
    ScVal::try_from_val(env, &key.into_val(env)).expect("storage key converts to ScVal")
}

fn short_scval(v: &ScVal) -> String {
    short_debug(v)
}

/// A full copy of the ledger entries, for before/after comparisons.
pub(crate) type Snapshot = Vec<(LedgerKey, Option<(LedgerEntry, Option<u32>)>)>;

pub(crate) fn snapshot(env: &Env) -> Snapshot {
    let mut snap: Snapshot = env
        .host()
        .get_stored_entries()
        .expect("reading test ledger storage")
        .iter()
        .map(|(k, v)| {
            (
                (**k).clone(),
                v.as_ref().map(|(e, ttl)| ((**e).clone(), *ttl)),
            )
        })
        .collect();
    snap.sort_by(|a, b| a.0.cmp(&b.0));
    snap
}

/// Describe every entry that was added, removed or changed (value or TTL).
pub(crate) fn changed_entries(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    let describe = |k: &LedgerKey| match k {
        LedgerKey::ContractData(d) => {
            format!(
                "{:?} data of {}: {}",
                d.durability,
                d.contract,
                short_scval(&d.key)
            )
        }
        other => short_debug(other),
    };
    let mut out = Vec::new();
    for (k, v) in after {
        match before.binary_search_by(|(bk, _)| bk.cmp(k)) {
            Ok(i) if before[i].1 == *v => {}
            Ok(_) => out.push(format!("changed {}", describe(k))),
            Err(_) => out.push(format!("created {}", describe(k))),
        }
    }
    for (k, _) in before {
        if after.binary_search_by(|(ak, _)| ak.cmp(k)).is_err() {
            out.push(format!("deleted {}", describe(k)));
        }
    }
    out
}

fn short_debug(v: &impl fmt::Debug) -> String {
    let s = format!("{v:?}");
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(160).collect::<String>())
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, symbol_short, Env};

    #[contract]
    pub struct TestContract;

    #[contractimpl]
    impl TestContract {
        pub fn put(env: Env, key: u32, val: u32) {
            env.storage().persistent().set(&key, &val);
        }

        pub fn remove(env: Env, key: u32) {
            env.storage().persistent().remove(&key);
        }
    }

    fn setup() -> (Env, Address) {
        let env = Env::default();
        let id = env.register(TestContract, ());
        (env, id)
    }

    #[test]
    fn changed_entries_empty_when_nothing_changed() {
        let (env, _id) = setup();
        let before = snapshot(&env);
        let after = snapshot(&env);
        assert!(changed_entries(&before, &after).is_empty());
    }

    #[test]
    fn changed_entries_reports_created_updated_removed() {
        let (env, id) = setup();
        let client = TestContractClient::new(&env, &id);

        client.put(&1, &10);
        client.put(&2, &20);
        let before = snapshot(&env);

        client.put(&3, &30); // created
        client.put(&1, &11); // updated
        client.remove(&2); // removed
        let after = snapshot(&env);

        let changes = changed_entries(&before, &after);
        assert_eq!(changes.len(), 3, "unexpected changes: {changes:?}");
        assert!(changes.iter().any(|c| c.starts_with("created ")));
        assert!(changes.iter().any(|c| c.starts_with("changed ")));
        assert!(changes.iter().any(|c| c.starts_with("deleted ")));
    }

    #[test]
    fn expired_respects_live_until_and_contract_filter() {
        let env = Env::default();
        let id = env.register(TestContract, ());
        let client = TestContractClient::new(&env, &id);
        client.put(&7, &70);

        let key = to_scval(&env, &7u32);
        let entry = find(&env, &id, Some(&key), Durability::Persistent)
            .expect("persistent entry exists");
        let live_until = entry.live_until;

        // At the boundary ledger the entry is still live.
        env.ledger().set_sequence_number(live_until);
        assert!(expired(&env, None).is_empty());

        // Past `live_until` the entry is expired.
        env.ledger().set_sequence_number(live_until + 1);
        let all = expired(&env, None);
        assert!(all.iter().any(|e| e.belongs_to(&id)));

        // Filtering by a different contract excludes it.
        let other = Address::generate(&env);
        assert!(expired(&env, Some(&[other])).is_empty());
        // Filtering by the owning contract includes it.
        assert!(expired(&env, Some(&[id.clone()]))
            .iter()
            .any(|e| e.belongs_to(&id)));
    }

    #[test]
    fn ttl_and_is_expired_at_boundary() {
        let entry = StoredEntry {
            contract: None,
            key: None,
            durability: Durability::Persistent,
            live_until: 100,
        };
        // `live_until` itself is still live.
        assert!(!entry.is_expired(100));
        assert_eq!(entry.ttl(100), 0);
        assert_eq!(entry.ttl(90), 10);
        // One ledger past the boundary is expired.
        assert!(entry.is_expired(101));
        assert_eq!(entry.ttl(101), 0);
    }
}
