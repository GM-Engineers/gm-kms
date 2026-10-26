//! PostgreSQL-backed tests for the **persisted** PBAC policy store
//! (audit follow-up B9-a).
//!
//! The PBAC engine keeps its policy set in memory, so before this change a
//! policy installed through the API vanished on the next restart. The engine
//! now writes through to a `policies` table and reloads it at startup, and
//! these cases check that against a real PostgreSQL:
//!
//! - a policy installed through the engine reaches the database;
//! - every field survives the round trip (the `effect` column in particular
//!   is stored in the serde form, not the `Debug` form);
//! - **a policy survives a restart** — a second engine over the same store
//!   loads it and still decides requests with it;
//! - a removed policy is removed from the database, not only from memory.
//!
//! These cases are `#[ignore]`d and gated on `DATABASE_URL`, like the other
//! PostgreSQL-backed tests in this repository.
//!
//! Run them against a real PostgreSQL with:
//!
//! ```text
//! export DATABASE_URL="postgres://kms:kms123@127.0.0.1:55432/kms"
//! cargo test --test api_policy_pg_integration -- --ignored --test-threads=1
//! ```

use std::sync::Arc;

use kms_api::sqlx::Row;
use kms_api::sqlx::postgres::PgPoolOptions;
use kms_core::PolicyEffect;
use kms_policy::{
    AccessContext, Decision, PBACEngine, Policy, PolicyRepository, PostgresPolicyRepository,
};
use serde_json::json;
use uuid::Uuid;

/// The connection string of the PostgreSQL under test.
fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://kms:kms123@localhost:5432/kms".to_string())
}

/// Connect to the database under test.
async fn pool() -> kms_api::sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url())
        .await
        .expect("connect to the PostgreSQL under test")
}

/// A policy that exercises every stored field.
fn sample_policy(effect: PolicyEffect, enabled: bool) -> Policy {
    Policy {
        id: Uuid::new_v4(),
        name: "pg-policy".to_string(),
        effect,
        condition: json!({
            "operator": "eq",
            "attribute": "subject.department",
            "value": "ops"
        }),
        resources: vec!["keys/prod/*".to_string()],
        subjects: vec!["service:api".to_string()],
        enabled,
    }
}

/// Remove every policy row so the cases do not depend on each other's state.
async fn clear_policies(pool: &kms_api::sqlx::PgPool) {
    kms_api::sqlx::query("DELETE FROM policies")
        .execute(pool)
        .await
        .expect("clear policies");
}

/// A policy installed through the engine must reach the database.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn test_installed_policy_reaches_the_database() {
    let pool = pool().await;
    let repository = Arc::new(PostgresPolicyRepository::new(pool.clone()));
    repository.migrate().await.expect("migrate");
    clear_policies(&pool).await;

    let engine = PBACEngine::new().with_repository(repository.clone());
    let policy = sample_policy(PolicyEffect::Deny, true);
    engine.add_policy(policy.clone()).await.expect("add policy");

    let row = kms_api::sqlx::query("SELECT id, name, effect FROM policies WHERE id = $1")
        .bind(policy.id)
        .fetch_one(&pool)
        .await
        .expect("the policy row must exist");

    assert_eq!(row.get::<Uuid, _>("id"), policy.id);
    assert_eq!(row.get::<String, _>("name"), "pg-policy");
    // The stored form is the serde one. The `Debug` form ("Deny") would not
    // survive the round trip.
    assert_eq!(row.get::<String, _>("effect"), "DENY");
}

/// Every field of a policy must survive the round trip through the database.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn test_every_field_survives_the_round_trip() {
    let pool = pool().await;
    let repository = Arc::new(PostgresPolicyRepository::new(pool.clone()));
    repository.migrate().await.expect("migrate");
    clear_policies(&pool).await;

    let engine = PBACEngine::new().with_repository(repository.clone());
    let policy = sample_policy(PolicyEffect::Allow, false);
    engine.add_policy(policy.clone()).await.expect("add policy");

    let stored = repository
        .load_all()
        .await
        .expect("load")
        .into_iter()
        .find(|p| p.id == policy.id)
        .expect("the policy must be in the store");

    assert_eq!(stored.id, policy.id);
    assert_eq!(stored.name, policy.name);
    assert_eq!(stored.effect, policy.effect);
    assert_eq!(stored.condition, policy.condition);
    assert_eq!(stored.resources, policy.resources);
    assert_eq!(stored.subjects, policy.subjects);
    // A disabled policy must stay disabled, or a policy the operator turned
    // off would come back on the next restart and start denying traffic.
    assert_eq!(stored.enabled, policy.enabled);
}

/// The decisive case: a policy must survive a restart.
///
/// A second engine over the same store stands in for the next process: it
/// loads the policy and still decides requests with it.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn test_policy_survives_a_restart() {
    let pool = pool().await;
    let repository = Arc::new(PostgresPolicyRepository::new(pool.clone()));
    repository.migrate().await.expect("migrate");
    clear_policies(&pool).await;

    // First "process": install a denying policy.
    let first = PBACEngine::new().with_repository(repository.clone());
    first
        .add_policy(sample_policy(PolicyEffect::Deny, true))
        .await
        .expect("add policy");

    // Second "process": a fresh engine over the same store.
    let restarted = PBACEngine::new().with_repository(repository.clone());
    let count = restarted.load_from_repository().await.expect("load");
    assert_eq!(count, 1);

    // The restored policy still decides requests.
    let ctx = AccessContext::new("service:api", "encrypt", "keys/prod/1");
    assert_eq!(
        restarted.evaluate(&ctx).await.expect("evaluate"),
        Decision::Deny
    );
}

/// A policy that the engine does not know about must not deny anything:
/// the reload restores exactly what was stored.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn test_reload_restores_exactly_the_stored_policies() {
    let pool = pool().await;
    let repository = Arc::new(PostgresPolicyRepository::new(pool.clone()));
    repository.migrate().await.expect("migrate");
    clear_policies(&pool).await;

    let first = PBACEngine::new().with_repository(repository.clone());
    let kept = sample_policy(PolicyEffect::Deny, true);
    first.add_policy(kept.clone()).await.expect("add policy");
    first
        .add_policy(sample_policy(PolicyEffect::Allow, true))
        .await
        .expect("add policy");

    let restarted = PBACEngine::new().with_repository(repository.clone());
    let count = restarted.load_from_repository().await.expect("load");
    assert_eq!(count, 2);

    let loaded = restarted.list_policies().await.expect("list");
    assert_eq!(loaded.len(), 2);
    assert!(loaded.iter().any(|p| p.id == kept.id));
}

/// A removed policy must leave the database too, or it would come back on
/// the next restart.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn test_removed_policy_is_removed_from_the_database() {
    let pool = pool().await;
    let repository = Arc::new(PostgresPolicyRepository::new(pool.clone()));
    repository.migrate().await.expect("migrate");
    clear_policies(&pool).await;

    let engine = PBACEngine::new().with_repository(repository.clone());
    let policy = sample_policy(PolicyEffect::Deny, true);
    engine.add_policy(policy.clone()).await.expect("add policy");

    engine
        .remove_policy(&policy.id)
        .await
        .expect("remove policy");

    let remaining = kms_api::sqlx::query("SELECT count(*) AS n FROM policies WHERE id = $1")
        .bind(policy.id)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(remaining.get::<i64, _>("n"), 0);

    // And it must not come back on the next restart.
    let restarted = PBACEngine::new().with_repository(repository.clone());
    let count = restarted.load_from_repository().await.expect("load");
    assert_eq!(count, 0);
}

/// The store must survive a schema that does not exist yet: the server
/// creates the table at startup, so a fresh deployment works.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn test_migrate_creates_the_table() {
    let pool = pool().await;
    kms_api::sqlx::query("DROP TABLE IF EXISTS policies")
        .execute(&pool)
        .await
        .expect("drop");

    let repository = PostgresPolicyRepository::new(pool.clone());
    repository.migrate().await.expect("migrate");
    repository.migrate().await.expect("migrate is idempotent");

    let count = repository.load_all().await.expect("load");
    assert!(count.is_empty());
}
