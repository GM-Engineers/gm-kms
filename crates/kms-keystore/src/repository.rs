//! PostgreSQL repository for keys
//!
//! Implements persistent storage for key metadata using sqlx.

use chrono::{DateTime, Utc};
use kms_core::error::Error;
use kms_core::key::{KeyMeta, KeySpec, KeyStatus};
use sqlx::{FromRow, Pool, Postgres, postgres::PgPoolOptions};

/// Key entity stored in PostgreSQL
#[derive(Debug, FromRow)]
pub struct KeyEntity {
    pub id: uuid::Uuid,
    pub tenant_id: String,
    pub name: String,
    pub spec: String,
    pub status: String,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Key version entity for tracking rotation history
#[derive(Debug, FromRow)]
pub struct KeyVersionEntity {
    pub id: uuid::Uuid,
    pub key_id: uuid::Uuid,
    pub version: i32,
    pub encrypted_dek: Option<Vec<u8>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

impl From<KeyEntity> for KeyMeta {
    fn from(e: KeyEntity) -> Self {
        let spec = match e.spec.as_str() {
            "Aes256Gcm" => KeySpec::Aes256Gcm,
            "Ed25519" => KeySpec::Ed25519,
            "EcdsaP256" => KeySpec::EcdsaP256,
            "Sm4" => KeySpec::Sm4,
            "Sm2" => KeySpec::Sm2,
            "HmacSha256" => KeySpec::HmacSha256,
            "Rsa4096" => KeySpec::Rsa4096,
            _ => KeySpec::Aes256Gcm,
        };

        let status = match e.status.as_str() {
            "Active" => KeyStatus::Active,
            "PendingDeletion" => KeyStatus::PendingDeletion,
            "Obsolete" => KeyStatus::Obsolete,
            "Destroyed" => KeyStatus::Destroyed,
            _ => KeyStatus::Active,
        };

        let metadata = e
            .metadata
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();

        KeyMeta {
            id: e.id,
            tenant_id: e.tenant_id,
            name: e.name,
            spec,
            status,
            version: e.version as u32,
            created_at: e.created_at,
            rotated_at: e.rotated_at,
            description: e.description,
            metadata,
        }
    }
}

/// PostgreSQL key repository
pub struct PostgresKeyRepository {
    pool: Pool<Postgres>,
}

impl PostgresKeyRepository {
    /// Create a new repository with the given connection pool
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// Create repository from DATABASE_URL environment variable.
    ///
    /// If `KMS_DB_TLS_MODE` is set, TLS parameters are appended to the URL.
    pub async fn from_env() -> Result<Self, sqlx::Error> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost:5432/kms".to_string());

        let tls_config = kms_core::BackendTlsConfig::from_env();
        let url = tls_config.build_postgres_url(&database_url);

        if tls_config.is_tls_enabled() {
            tracing::info!(
                mode = %tls_config.mode,
                "Connecting to PostgreSQL with TLS"
            );
        }

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await?;

        Ok(Self::new(pool))
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        // Create tables if they don't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS keys (
                id UUID PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                spec TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                version INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                rotated_at TIMESTAMPTZ,
                description TEXT,
                metadata JSONB DEFAULT '{}',
                encrypted_material BYTEA,
                deleted_at TIMESTAMPTZ,
                deleted_by TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create key_versions table for rotation history
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS key_versions (
                id UUID PRIMARY KEY,
                key_id UUID NOT NULL REFERENCES keys(id),
                version INTEGER NOT NULL,
                encrypted_dek BYTEA,
                status TEXT NOT NULL DEFAULT 'Active',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                rotated_at TIMESTAMPTZ,
                UNIQUE(key_id, version)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_keys_tenant_id ON keys(tenant_id)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_key_versions_key_id ON key_versions(key_id)
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Insert a new key
    pub async fn insert(&self, meta: &KeyMeta) -> Result<(), Error> {
        let spec_str = format!("{:?}", meta.spec);
        let status_str = format!("{:?}", meta.status);
        let metadata = serde_json::to_value(&meta.metadata)
            .unwrap_or(serde_json::Value::Object(Default::default()));

        sqlx::query(
            r#"
            INSERT INTO keys (id, tenant_id, name, spec, status, version, created_at, rotated_at, description, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(meta.id)
        .bind(&meta.tenant_id)
        .bind(&meta.name)
        .bind(&spec_str)
        .bind(&status_str)
        .bind(meta.version as i32)
        .bind(meta.created_at)
        .bind(meta.rotated_at)
        .bind(&meta.description)
        .bind(metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    /// Find a key by ID
    pub async fn find_by_id(&self, id: &uuid::Uuid) -> Result<Option<KeyMeta>, Error> {
        let row: Option<KeyEntity> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, spec, status, version, created_at, rotated_at, description, metadata
            FROM keys
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(row.map(KeyMeta::from))
    }

    /// Find encrypted key material by key ID
    pub async fn find_encrypted_material(&self, id: &uuid::Uuid) -> Result<Option<Vec<u8>>, Error> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            r#"
            SELECT encrypted_material
            FROM keys
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(row.map(|(material,)| material))
    }

    /// Update encrypted key material for a key
    pub async fn update_encrypted_material(
        &self,
        id: &uuid::Uuid,
        encrypted_material: &[u8],
    ) -> Result<(), Error> {
        sqlx::query(
            r#"
            UPDATE keys
            SET encrypted_material = $2
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id)
        .bind(encrypted_material)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    /// List keys with optional filters
    /// List keys by tenant (tenant_id is always required for tenant isolation).
    pub async fn list(
        &self,
        tenant_id: &str,
        _status: Option<&str>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<KeyMeta>, Error> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let rows: Vec<KeyEntity> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, spec, status, version, created_at, rotated_at, description, metadata
            FROM keys
            WHERE tenant_id = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(rows.into_iter().map(KeyMeta::from).collect())
    }

    /// Internal use only: list all keys across all tenants (e.g., server startup).
    /// Must never be exposed via public API.
    pub(crate) async fn list_all_tenants(
        &self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<KeyMeta>, Error> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let rows: Vec<KeyEntity> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, spec, status, version, created_at, rotated_at, description, metadata
            FROM keys
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(rows.into_iter().map(KeyMeta::from).collect())
    }

    /// Update key status
    pub async fn update_status(&self, id: &uuid::Uuid, status: KeyStatus) -> Result<(), Error> {
        let status_str = format!("{:?}", status);

        sqlx::query(
            r#"
            UPDATE keys SET status = $2 WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id)
        .bind(&status_str)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    /// Soft delete a key
    pub async fn soft_delete(&self, id: &uuid::Uuid, deleted_by: &str) -> Result<(), Error> {
        sqlx::query(
            r#"
            UPDATE keys SET deleted_at = NOW(), deleted_by = $2 WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id)
        .bind(deleted_by)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    /// Insert a key version record
    pub async fn insert_version(
        &self,
        key_id: &uuid::Uuid,
        version: u32,
        encrypted_dek: Option<&[u8]>,
        status: &str,
    ) -> Result<uuid::Uuid, Error> {
        let id = uuid::Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO key_versions (id, key_id, version, encrypted_dek, status, created_at, rotated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(key_id)
        .bind(version as i32)
        .bind(encrypted_dek)
        .bind(status)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(id)
    }

    /// List all versions of a key
    pub async fn list_versions(&self, key_id: &uuid::Uuid) -> Result<Vec<KeyVersionEntity>, Error> {
        let rows: Vec<KeyVersionEntity> = sqlx::query_as(
            r#"
            SELECT id, key_id, version, encrypted_dek, status, created_at, rotated_at
            FROM key_versions
            WHERE key_id = $1
            ORDER BY version DESC
            "#,
        )
        .bind(key_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(rows)
    }

    /// Get a specific version of a key
    pub async fn get_version(
        &self,
        key_id: &uuid::Uuid,
        version: u32,
    ) -> Result<Option<KeyVersionEntity>, Error> {
        let row: Option<KeyVersionEntity> = sqlx::query_as(
            r#"
            SELECT id, key_id, version, encrypted_dek, status, created_at, rotated_at
            FROM key_versions
            WHERE key_id = $1 AND version = $2
            "#,
        )
        .bind(key_id)
        .bind(version as i32)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(row)
    }

    /// Update the current version of a key (after rotation)
    pub async fn update_version_rotated_at(
        &self,
        key_id: &uuid::Uuid,
        version: u32,
    ) -> Result<(), Error> {
        let now = Utc::now();

        sqlx::query(
            r#"
            UPDATE key_versions SET rotated_at = $3, status = 'Rotated'
            WHERE key_id = $1 AND version = $2
            "#,
        )
        .bind(key_id)
        .bind(version as i32)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires running server (Redis/PostgreSQL)
    async fn test_postgres_repository_crud() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://kms:kms123@localhost:5432/kms".to_string());

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("Failed to connect to PostgreSQL");

        let repo = PostgresKeyRepository::new(pool);

        // Run migrations
        repo.migrate().await.expect("Migration failed");

        // Test insert and find
        let now = chrono::Utc::now();
        let key_meta = kms_core::key::KeyMeta {
            id: uuid::Uuid::new_v4(),
            tenant_id: "test-tenant".to_string(),
            name: "test-key".to_string(),
            spec: kms_core::key::KeySpec::Aes256Gcm,
            status: kms_core::key::KeyStatus::Active,
            created_at: now,
            rotated_at: None,
            version: 1,
            description: None,
            metadata: Default::default(),
        };

        repo.insert(&key_meta).await.expect("Insert failed");

        // Find by ID
        let found = repo.find_by_id(&key_meta.id).await.expect("Find failed");
        assert!(found.is_some());
        let found_meta = found.unwrap();
        assert_eq!(found_meta.name, "test-key");
        assert_eq!(found_meta.tenant_id, "test-tenant");

        // List keys
        let keys = repo
            .list("test-tenant", None, None, None)
            .await
            .expect("List failed");
        assert!(!keys.is_empty());

        // Cleanup - soft delete
        repo.soft_delete(&key_meta.id, "test")
            .await
            .expect("Delete failed");

        println!("PostgreSQL repository CRUD test passed!");
    }

    #[tokio::test]
    #[ignore] // Requires running server (Redis/PostgreSQL)
    async fn test_postgres_version_tracking() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://kms:kms123@localhost:5432/kms".to_string());

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("Failed to connect to PostgreSQL");

        let repo = PostgresKeyRepository::new(pool);
        repo.migrate().await.expect("Migration failed");

        // Create a key first
        let key_meta = kms_core::key::KeyMeta {
            id: uuid::Uuid::new_v4(),
            tenant_id: "test-tenant".to_string(),
            name: "versioned-key".to_string(),
            spec: kms_core::key::KeySpec::Aes256Gcm,
            status: kms_core::key::KeyStatus::Active,
            created_at: chrono::Utc::now(),
            rotated_at: None,
            version: 1,
            description: None,
            metadata: Default::default(),
        };

        repo.insert(&key_meta).await.expect("Insert failed");

        // Insert a version
        let version_id = repo
            .insert_version(
                &key_meta.id,
                1,
                Some(b"encrypted_dek_placeholder"),
                "Active",
            )
            .await
            .expect("Insert version failed");

        assert!(!version_id.is_nil());

        // List versions
        let versions = repo
            .list_versions(&key_meta.id)
            .await
            .expect("List versions failed");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, 1);

        // Get specific version
        let v = repo
            .get_version(&key_meta.id, 1)
            .await
            .expect("Get version failed");
        assert!(v.is_some());

        println!("PostgreSQL version tracking test passed!");
    }
}
