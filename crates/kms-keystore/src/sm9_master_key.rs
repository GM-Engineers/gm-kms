//! SM9 Master Key PostgreSQL Repository
//!
//! This module provides PostgreSQL-based persistence for the SM9 master key,
//! integrated with kms-core's Sm9MasterKeyStore trait for KEK protection.

use async_trait::async_trait;
use kms_core::sm9_master_key::Sm9MasterKeyStore;
use kms_core::{Error, Result};
use std::sync::Arc;

/// Repository trait for SM9 master key persistence (PostgreSQL implementation)
#[async_trait]
pub trait Sm9MasterKeyRepository: Send + Sync {
    /// Store the master key (will be encrypted before storage via KEK store)
    async fn store(&self, key: &[u8], version: u32) -> Result<()>;

    /// Load the master key (will be decrypted after retrieval via KEK store)
    async fn load(&self) -> Result<Vec<u8>>;

    /// Get current version of stored master key
    async fn get_version(&self) -> Result<Option<u32>>;

    /// Check if a master key exists
    async fn exists(&self) -> Result<bool>;

    /// Delete the master key (for key rotation scenarios)
    async fn delete(&self) -> Result<()>;
}

/// PostgreSQL-based SM9 master key repository
///
/// SECURITY NOTE: `table_name` is currently hardcoded to "sm9_master_key" and
/// not derived from user input, so SQL injection via format!() is not exploitable.
/// However, if `table_name` ever becomes configurable, it MUST be validated
/// against an allowlist before use in format!() queries. Consider using
/// `sqlx::query!()` or `sqlx::query_as!()` compile-time checked queries instead.
pub struct PostgresSm9MasterKeyRepository<S: Sm9MasterKeyStore> {
    pool: sqlx::PgPool,
    store: Arc<S>,
    table_name: String,
}

impl<S: Sm9MasterKeyStore> PostgresSm9MasterKeyRepository<S> {
    /// Create new repository with PostgreSQL pool and KEK store
    pub fn new(pool: sqlx::PgPool, store: Arc<S>) -> Self {
        Self {
            pool,
            store,
            table_name: "sm9_master_key".to_string(),
        }
    }

    /// Initialize the database table if not exists
    pub async fn init(&self) -> Result<()> {
        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
                version INTEGER NOT NULL DEFAULT 1,
                encrypted_key BYTEA NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
            self.table_name
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl<S: Sm9MasterKeyStore + 'static> Sm9MasterKeyRepository for PostgresSm9MasterKeyRepository<S> {
    async fn store(&self, key: &[u8], version: u32) -> Result<()> {
        // Encrypt with KEK first
        let encrypted = self.store.encrypt(key).await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {} (id, version, encrypted_key, updated_at)
            VALUES (1, $1, $2, NOW())
            ON CONFLICT (id) DO UPDATE SET
                version = $1,
                encrypted_key = $2,
                updated_at = NOW()
            "#,
            self.table_name
        ))
        .bind(version as i32)
        .bind(&encrypted)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    async fn load(&self) -> Result<Vec<u8>> {
        let row: (Vec<u8>,) = sqlx::query_as(&format!(
            "SELECT encrypted_key FROM {} WHERE id = 1",
            self.table_name
        ))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        // Decrypt with KEK
        self.store.decrypt(&row.0).await
    }

    async fn get_version(&self) -> Result<Option<u32>> {
        let row: Option<(i32,)> = sqlx::query_as(&format!(
            "SELECT version FROM {} WHERE id = 1",
            self.table_name
        ))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(row.map(|r| r.0 as u32))
    }

    async fn exists(&self) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as(&format!("SELECT 1 FROM {} WHERE id = 1", self.table_name))
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(row.is_some())
    }

    async fn delete(&self) -> Result<()> {
        sqlx::query(&format!("DELETE FROM {} WHERE id = 1", self.table_name))
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }
}
