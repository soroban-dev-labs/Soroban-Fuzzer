//! Read storage TTLs from outside a contract, for use in invariants.
//!
//! These helpers read the raw test ledger, so unlike the SDK's `get_ttl` they
//! never restore an archived entry as a side effect. Each returns the number
//! of ledgers the entry has left (`live_until - current_sequence`), `Some(0)`
//! for an expired (archived) persistent entry, or `None` if there is no such
//! entry. Expired temporary entries count as deleted and return `None`.

use soroban_sdk::{Address, Env, IntoVal, Val};

use crate::storage::{find, to_scval, Durability};

/// TTL of a persistent entry of `contract`.
pub fn persistent<K: IntoVal<Env, Val>>(env: &Env, contract: &Address, key: &K) -> Option<u32> {
    let key = to_scval(env, key);
    find(env, contract, Some(&key), Durability::Persistent).map(|e| e.ttl(env.ledger().sequence()))
}

/// TTL of a temporary entry of `contract`.
pub fn temporary<K: IntoVal<Env, Val>>(env: &Env, contract: &Address, key: &K) -> Option<u32> {
    let seq = env.ledger().sequence();
    let key = to_scval(env, key);
    find(env, contract, Some(&key), Durability::Temporary)
        .filter(|e| !e.is_expired(seq))
        .map(|e| e.ttl(seq))
}

/// TTL of the contract instance (and its instance storage).
pub fn instance(env: &Env, contract: &Address) -> Option<u32> {
    find(env, contract, None, Durability::Instance).map(|e| e.ttl(env.ledger().sequence()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{changed_entries, expired, snapshot, StoredEntry};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{contract, contractimpl, symbol_short, Env};

    #[contract]
    pub struct TinyContract;

    #[contractimpl]
    impl TinyContract {
        pub fn put(env: Env, key: u32, val: u32) {
            env.storage().persistent().set(&key, &val);
        }

        pub fn remove(env: Env, key: u32) {
            env.storage().persistent().remove(&key);
        }

        pub fn bump(env: Env, key: u32, live_until: u32) {
            env.storage().persistent().extend_ttl(&key, live_until, live_until);
        }
    }

    fn setup() -> (Env, Address) {
        let env = Env::default();
        let id = env.register_contract(None, TinyContract);
        (env, id)
    }

    #[test]
    fn changed_entries_empty_when_nothing_changed() {
        let (env, id) = setup();
        let before = snapshot(&env);
        let changed = changed_entries(&env, &before);
        assert!(changed.is_empty());
        let _ = id;
    }

    #[test]
    fn changed_entries_lists_created_updated_removed() {
        let (env, id) = setup();
        let client = TinyContractClient::new(&env, &id);
        client.put(&1u32, &10u32);
        client.put(&2u32, &20u32);
        client.put(&3u32, &30u32);

        let before = snapshot(&env);

        client.put(&1u32, &11u32); // updated
        client.remove(&2u32); // removed
        client.put(&4u32, &40u32); // created

        let changed = changed_entries(&env, &before);
        assert_eq!(changed.len(), 3);
        let _ = symbol_short!("x");
    }

    #[test]
    fn expired_respects_live_until_and_contract_filter() {
        let (env, id) = setup();
        let client = TinyContractClient::new(&env, &id);
        client.put(&1u32, &10u32);
        client.bump(&1u32, &(env.ledger().sequence() + 5));

        let live_until = env.ledger().sequence() + 5;
        assert!(expired(&env, &id).is_empty());

        env.ledger().set_sequence_number(live_until + 1);
        let exp = expired(&env, &id);
        assert_eq!(exp.len(), 1);

        let other = Address::generate(&env);
        assert!(expired(&env, &other).is_empty());
    }

    #[test]
    fn ttl_and_is_expired_at_boundary() {
        let (env, id) = setup();
        let client = TinyContractClient::new(&env, &id);
        client.put(&1u32, &10u32);
        let live_until = env.ledger().sequence() + 5;
        client.bump(&1u32, &live_until);

        let entry: StoredEntry = find(&env, &id, Some(&to_scval(&env, &1u32)), Durability::Persistent)
            .expect("entry exists");

        // At the boundary ledger the entry is still live.
        assert_eq!(entry.ttl(live_until), 0);
        assert!(!entry.is_expired(live_until));

        // One ledger past the boundary it is expired.
        assert!(entry.is_expired(live_until + 1));
    }
}
