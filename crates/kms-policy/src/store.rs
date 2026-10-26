//! Durable storage for PBAC policies.
//!
//! [`PBACEngine`](crate::PBACEngine) evaluates policies out of an in-memory
//! map, so this repository is the durable half of the policy store: it is
//! what makes an installed policy survive a restart instead of silently
//! disappearing from the engine (audit follow-up B9-a).
//!
//! The engine holds an optional repository and writes through it, so there is
//! no code path that installs a policy only in memory. A policy the API
//! accepted is a policy that is stored; if the store rejects the write, the
//! API reports the failure and the engine keeps its previous set.

use super::Policy;
use async_trait::async_trait;
use kms_core::PolicyEffect;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Errors raised by a [`PolicyRepository`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyStoreError {
    /// The store could not be reached, or the query failed.
    #[error("policy store unavailable: {0}")]
    Unavailable(String),
    /// A stored row could not be decoded into a [`Policy`].
    #[error("stored policy is malformed: {0}")]
    Malformed(String),
}

/// Durable storage for policies.
///
/// Implementations are expected to be safe to share across tasks: the engine
/// holds one behind an `Arc` and calls it from request handlers.
#[async_trait]
pub trait PolicyRepository: Send + Sync {
    /// Create the backing schema if it does not exist yet.
    async fn migrate(&self) -> Result<(), PolicyStoreError>;

    /// Load every stored policy.
    ///
    /// An error here must never be reported as "there are no policies": the
    /// caller cannot tell an empty store from an unreadable one, and
    /// mistaking the second for the first silently disables attribute-based
    /// control. The server treats a failure as fatal for that reason.
    async fn load_all(&self) -> Result<Vec<Policy>, PolicyStoreError>;

    /// Insert a policy, replacing an existing row with the same ID.
    async fn save(&self, policy: &Policy) -> Result<(), PolicyStoreError>;

    /// Delete a policy. Returns `true` when a row was removed.
    async fn delete(&self, id: &Uuid) -> Result<bool, PolicyStoreError>;
}

/// PostgreSQL-backed policy repository.
///
/// Mirrors the `PostgresKeyRepository` pattern of the `kms-keystore` crate:
/// the schema is created with `CREATE TABLE IF NOT EXISTS` at startup rather
/// than through a migration tool, so an existing deployment picks the table
/// up on its next start.
#[derive(Clone)]
pub struct PostgresPolicyRepository {
    pool: PgPool,
}

impl PostgresPolicyRepository {
    /// Create a repository over an existing connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyRepository for PostgresPolicyRepository {
    async fn migrate(&self) -> Result<(), PolicyStoreError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policies (
                id UUID PRIMARY KEY,
                name TEXT NOT NULL,
                effect TEXT NOT NULL,
                condition JSONB NOT NULL,
                resources TEXT[] NOT NULL DEFAULT '{}',
                subjects TEXT[] NOT NULL DEFAULT '{}',
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyStoreError::Unavailable(format!("create policies table: {e}")))?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyStoreError::Unavailable(format!("create policies index: {e}")))?;

        Ok(())
    }

    async fn load_all(&self) -> Result<Vec<Policy>, PolicyStoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, effect, condition, resources, subjects, enabled
            FROM policies
            ORDER BY created_at, id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| PolicyStoreError::Unavailable(format!("load policies: {e}")))?;

        rows.iter().map(row_to_policy).collect()
    }

    async fn save(&self, policy: &Policy) -> Result<(), PolicyStoreError> {
        let effect = effect_to_db(&policy.effect)?;

        sqlx::query(
            r#"
            INSERT INTO policies (id, name, effect, condition, resources, subjects, enabled, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                effect = EXCLUDED.effect,
                condition = EXCLUDED.condition,
                resources = EXCLUDED.resources,
                subjects = EXCLUDED.subjects,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()
            "#,
        )
        .bind(policy.id)
        .bind(&policy.name)
        .bind(effect)
        .bind(&policy.condition)
        .bind(&policy.resources)
        .bind(&policy.subjects)
        .bind(policy.enabled)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyStoreError::Unavailable(format!("save policy {}: {e}", policy.id)))?;

        Ok(())
    }

    async fn delete(&self, id: &Uuid) -> Result<bool, PolicyStoreError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| PolicyStoreError::Unavailable(format!("delete policy {id}: {e}")))?;

        Ok(result.rows_affected() > 0)
    }
}

/// Encode an effect for storage.
///
/// The stored form is the serde representation of [`PolicyEffect`]
/// (`SCREAMING_SNAKE_CASE`, so `ALLOW` / `DENY`) — not its `Debug` form
/// (`Allow` / `Deny`). The two differ, and mixing them would break the
/// round-trip: a row written by one form could not be read back by the other.
fn effect_to_db(effect: &PolicyEffect) -> Result<String, PolicyStoreError> {
    let encoded = serde_json::to_value(effect)
        .map_err(|e| PolicyStoreError::Malformed(format!("encode effect: {e}")))?;

    encoded
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| PolicyStoreError::Malformed("effect did not encode to a string".to_string()))
}

/// Decode a stored effect.
fn effect_from_db(raw: &str) -> Result<PolicyEffect, PolicyStoreError> {
    serde_json::from_value(serde_json::Value::String(raw.to_string()))
        .map_err(|e| PolicyStoreError::Malformed(format!("unknown policy effect {raw:?}: {e}")))
}

/// Decode one row into a [`Policy`].
fn row_to_policy(row: &PgRow) -> Result<Policy, PolicyStoreError> {
    let id: Uuid = row
        .try_get("id")
        .map_err(|e| PolicyStoreError::Malformed(format!("read id: {e}")))?;
    let name: String = row
        .try_get("name")
        .map_err(|e| PolicyStoreError::Malformed(format!("read name: {e}")))?;
    let effect_raw: String = row
        .try_get("effect")
        .map_err(|e| PolicyStoreError::Malformed(format!("read effect: {e}")))?;
    let condition: serde_json::Value = row
        .try_get("condition")
        .map_err(|e| PolicyStoreError::Malformed(format!("read condition: {e}")))?;
    let resources: Vec<String> = row
        .try_get("resources")
        .map_err(|e| PolicyStoreError::Malformed(format!("read resources: {e}")))?;
    let subjects: Vec<String> = row
        .try_get("subjects")
        .map_err(|e| PolicyStoreError::Malformed(format!("read subjects: {e}")))?;
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|e| PolicyStoreError::Malformed(format!("read enabled: {e}")))?;

    Ok(Policy {
        id,
        name,
        effect: effect_from_db(&effect_raw)?,
        condition,
        resources,
        subjects,
        enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_round_trips_through_the_database_form() {
        for effect in [PolicyEffect::Allow, PolicyEffect::Deny] {
            let encoded = effect_to_db(&effect).expect("encode");
            assert_eq!(encoded, encoded.to_uppercase());
            let decoded = effect_from_db(&encoded).expect("decode");
            assert_eq!(decoded, effect);
        }
    }

    #[test]
    fn effect_uses_the_serde_form_not_the_debug_form() {
        // The stored form must be the serde one. The Debug form ("Allow")
        // would not survive the round-trip and is a silent corruption.
        assert_eq!(effect_to_db(&PolicyEffect::Allow).unwrap(), "ALLOW");
        assert_eq!(effect_to_db(&PolicyEffect::Deny).unwrap(), "DENY");
    }

    #[test]
    fn unknown_effect_is_rejected() {
        let err = effect_from_db("MAYBE").expect_err("must reject");
        assert!(matches!(err, PolicyStoreError::Malformed(_)));
    }
}
