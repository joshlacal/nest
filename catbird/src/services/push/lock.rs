use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};

/// Deterministic 64-bit advisory lock key for an account DID.
pub fn advisory_lock_key_for_account(did: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"push_account_lock:");
    hasher.update(did.as_bytes());
    let hash = hasher.finalize();
    i64::from_be_bytes(hash[..8].try_into().unwrap())
}

/// Deterministic 64-bit advisory lock key for a device token.
pub fn advisory_lock_key_for_device(token: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"push_device_lock:");
    hasher.update(token.as_bytes());
    let hash = hasher.finalize();
    i64::from_be_bytes(hash[..8].try_into().unwrap())
}

/// Acquires a transaction-level advisory lock for an account DID.
/// The lock is automatically released when the transaction commits or aborts.
pub async fn acquire_account_lock(
    tx: &mut Transaction<'_, Postgres>,
    did: &str,
) -> Result<()> {
    let key = advisory_lock_key_for_account(did);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Acquires transaction-level advisory locks for an account DID and device token.
/// Always acquires the account lock first, then the device lock, ensuring a uniform
/// hierarchical locking order that prevents deadlocks across all concurrent transactions.
pub async fn acquire_account_and_device_lock(
    tx: &mut Transaction<'_, Postgres>,
    did: &str,
    token: &str,
) -> Result<()> {
    let acc_key = advisory_lock_key_for_account(did);
    let dev_key = advisory_lock_key_for_device(token);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(acc_key)
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(dev_key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advisory_lock_keys_deterministic_and_domain_separated() {
        let did = "did:plc:testuser123456789";
        let token = "7777888899990000111122223333444477778888999900001111222233334444";

        let acc_key_1 = advisory_lock_key_for_account(did);
        let acc_key_2 = advisory_lock_key_for_account(did);
        assert_eq!(acc_key_1, acc_key_2, "Account key must be deterministic");

        let dev_key_1 = advisory_lock_key_for_device(token);
        let dev_key_2 = advisory_lock_key_for_device(token);
        assert_eq!(dev_key_1, dev_key_2, "Device key must be deterministic");

        // Domain separation check: same input string produces different keys for account vs device
        let test_str = "shared_identity_string";
        let acc_k = advisory_lock_key_for_account(test_str);
        let dev_k = advisory_lock_key_for_device(test_str);
        assert_ne!(acc_k, dev_k, "Account and device lock keys must be domain separated");
    }
}
