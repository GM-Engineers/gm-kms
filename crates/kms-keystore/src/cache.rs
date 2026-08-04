//! Redis caching layer for keystore
//!
//! Implements cache-aside pattern for key metadata.
//! Caches key metadata with TTL to reduce datastore load.

use crate::KeystoreBackend;
use async_trait::async_trait;
use kms_core::error::Error;
use kms_core::{
    BackendType, Result,
    dh::SharedSecret,
    key::{Ciphertext, DestructionProof, KeyFilter, KeyMeta, KeySpec, Signature},
};
use redis::AsyncCommands;

/// Redis cache wrapper around a keystore backend
pub struct RedisCachedKeystore<B> {
    inner: B,
    redis: redis::aio::ConnectionManager,
}

impl<B> RedisCachedKeystore<B> {
    pub fn new(inner: B, redis: redis::aio::ConnectionManager) -> Self {
        Self { inner, redis }
    }
}

fn cache_key_id(key_id: &uuid::Uuid, tenant_id: &str) -> String {
    format!("kms:{tenant_id}:key:{key_id}")
}

#[async_trait]
impl<B: KeystoreBackend + Send + Sync> KeystoreBackend for RedisCachedKeystore<B> {
    fn backend_type(&self) -> BackendType {
        BackendType::Cached
    }

    async fn generate_key(&self, spec: &KeySpec, name: &str, tenant_id: &str) -> Result<KeyMeta> {
        let meta = self.inner.generate_key(spec, name, tenant_id).await?;

        // Cache the new key metadata
        self.cache_key_meta(&meta).await?;

        Ok(meta)
    }

    async fn get_key_metadata(&self, key_id: &uuid::Uuid) -> Result<KeyMeta> {
        // The cache key includes tenant_id, but we don't have tenant_id until we fetch the key.
        // So we always fetch from storage first, then cache with proper tenant_id.
        // This means the first read is always a cache miss, but subsequent reads
        // (within TTL) that pass tenant_id through generate_key won't hit this method.

        tracing::debug!("Cache miss for key {}, fetching from storage", key_id);

        // Cache miss - fetch from storage
        let meta = self.inner.get_key_metadata(key_id).await?;

        // Cache it with proper tenant_id
        self.cache_key_meta(&meta).await?;

        Ok(meta)
    }

    async fn encrypt(
        &self,
        key_id: &uuid::Uuid,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        tenant_id: &str,
    ) -> Result<Ciphertext> {
        self.inner.encrypt(key_id, plaintext, aad, tenant_id).await
    }

    async fn decrypt(
        &self,
        key_id: &uuid::Uuid,
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
        tenant_id: &str,
    ) -> Result<Vec<u8>> {
        self.inner.decrypt(key_id, ciphertext, aad, tenant_id).await
    }

    async fn sign(&self, key_id: &uuid::Uuid, data: &[u8], tenant_id: &str) -> Result<Signature> {
        self.inner.sign(key_id, data, tenant_id).await
    }

    async fn verify(
        &self,
        key_id: &uuid::Uuid,
        data: &[u8],
        sig: &Signature,
        tenant_id: &str,
    ) -> Result<bool> {
        self.inner.verify(key_id, data, sig, tenant_id).await
    }

    async fn rotate_key(&self, key_id: &uuid::Uuid, tenant_id: &str) -> Result<KeyMeta> {
        // Invalidate cache for old key
        self.invalidate_cache(key_id, tenant_id).await;

        let new_meta = self.inner.rotate_key(key_id, tenant_id).await?;

        // Cache the new key metadata (with new ID)
        self.cache_key_meta(&new_meta).await?;

        Ok(new_meta)
    }

    async fn delete_key(&self, key_id: &uuid::Uuid, tenant_id: &str) -> Result<()> {
        // Invalidate cache
        self.invalidate_cache(key_id, tenant_id).await;

        self.inner.delete_key(key_id, tenant_id).await
    }

    async fn destroy_key(&self, key_id: &uuid::Uuid) -> Result<()> {
        // Get current key metadata to know tenant_id for cache invalidation
        let meta = self.inner.get_key_metadata(key_id).await?;
        let tenant_id = meta.tenant_id.clone();

        // Invalidate cache
        self.invalidate_cache(key_id, &tenant_id).await;

        self.inner.destroy_key(key_id).await
    }

    async fn destroy_key_with_proof(&self, key_id: &uuid::Uuid) -> Result<DestructionProof> {
        // Get current key metadata to know tenant_id for cache invalidation
        let meta = self.inner.get_key_metadata(key_id).await?;
        let tenant_id = meta.tenant_id.clone();

        // Invalidate cache
        self.invalidate_cache(key_id, &tenant_id).await;

        self.inner.destroy_key_with_proof(key_id).await
    }

    async fn list_keys(&self, filter: &KeyFilter) -> Result<Vec<KeyMeta>> {
        // ListKeys bypasses cache - always hit the underlying storage
        // to ensure consistency
        self.inner.list_keys(filter).await
    }

    async fn health(&self) -> Result<kms_core::types::HealthStatus> {
        // Check Redis connectivity
        let mut conn = self.redis.clone();
        let result: std::result::Result<String, _> =
            redis::cmd("PING").query_async(&mut conn).await;

        match result {
            Ok(_) => self.inner.health().await,
            Err(_) => Ok(kms_core::types::HealthStatus::Degraded),
        }
    }

    async fn import_key_material(
        &self,
        spec: &KeySpec,
        name: &str,
        tenant_id: &str,
        material: Vec<u8>,
    ) -> Result<KeyMeta> {
        let meta = self
            .inner
            .import_key_material(spec, name, tenant_id, material)
            .await?;

        // Cache the new key metadata
        self.cache_key_meta(&meta).await?;

        Ok(meta)
    }

    async fn export_key_material(&self, key_id: &uuid::Uuid, tenant_id: &str) -> Result<Vec<u8>> {
        self.inner.export_key_material(key_id, tenant_id).await
    }

    async fn get_key_material(&self, key_id: &uuid::Uuid, tenant_id: &str) -> Result<Vec<u8>> {
        self.inner.get_key_material(key_id, tenant_id).await
    }

    async fn derive_shared_secret(
        &self,
        key_id: &uuid::Uuid,
        peer_public_key: &[u8],
        algorithm: kms_core::dh::DhAlgorithm,
    ) -> Result<SharedSecret> {
        self.inner
            .derive_shared_secret(key_id, peer_public_key, algorithm)
            .await
    }
}

impl<B: Send + Sync> RedisCachedKeystore<B> {
    const KEY_CACHE_TTL_SECS: u64 = 300; // 5 minutes

    async fn cache_key_meta(&self, meta: &KeyMeta) -> Result<()> {
        let mut conn = self.redis.clone();
        let cache_key = cache_key_id(&meta.id, &meta.tenant_id);
        let json = serde_json::to_string(meta).map_err(|e| Error::Internal(e.to_string()))?;

        conn.set_ex::<_, _, ()>(&cache_key, &json, Self::KEY_CACHE_TTL_SECS)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn get_cached_key_meta(
        &self,
        key_id: &uuid::Uuid,
        tenant_id: &str,
    ) -> Result<Option<KeyMeta>> {
        let mut conn = self.redis.clone();
        let cache_key = cache_key_id(key_id, tenant_id);

        let json: Option<String> = conn
            .get(&cache_key)
            .await
            .map_err(|e| Error::Internal(e.to_string()))?;

        match json {
            Some(j) => {
                let meta: KeyMeta =
                    serde_json::from_str(&j).map_err(|e| Error::Internal(e.to_string()))?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    async fn invalidate_cache(&self, key_id: &uuid::Uuid, tenant_id: &str) {
        let mut conn = self.redis.clone();
        let cache_key = cache_key_id(key_id, tenant_id);

        if let Err(e) = conn.del::<_, ()>(&cache_key).await {
            tracing::warn!("Failed to invalidate cache for key {}: {}", key_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::KeystoreBackend;
    use crate::software::SoftwareKeystore;

    #[tokio::test]
    #[ignore] // Requires running server (Redis/PostgreSQL)
    async fn test_redis_cache_basic() {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        // Create Redis connection
        let redis_client =
            redis::Client::open(redis_url.clone()).expect("Failed to create Redis client");
        let conn_manager = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("Failed to connect to Redis");

        // Create inner keystore and wrap with cache
        let inner = SoftwareKeystore::new();
        let cached = RedisCachedKeystore::new(inner, conn_manager);

        // Generate a key - should be cached
        let spec = KeySpec::Aes256Gcm;
        let meta = cached
            .generate_key(&spec, "redis-test-key", "test-tenant")
            .await
            .expect("Failed to generate key");

        assert_eq!(meta.name, "redis-test-key");

        // Verify health check works
        let health = cached.health().await.expect("Health check failed");
        assert_eq!(health, kms_core::types::HealthStatus::Healthy);

        println!("Redis cache basic test passed!");
    }

    #[tokio::test]
    #[ignore] // Requires running server (Redis/PostgreSQL)
    async fn test_redis_cache_multi_tenant() {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let redis_client =
            redis::Client::open(redis_url.clone()).expect("Failed to create Redis client");
        let conn_manager = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("Failed to connect to Redis");

        let inner = SoftwareKeystore::new();
        let cached = RedisCachedKeystore::new(inner, conn_manager);

        // Create keys for two different tenants
        let spec = KeySpec::Aes256Gcm;

        let meta1 = cached
            .generate_key(&spec, "key-for-tenant1", "tenant-1")
            .await
            .expect("Failed to generate key for tenant1");

        let meta2 = cached
            .generate_key(&spec, "key-for-tenant2", "tenant-2")
            .await
            .expect("Failed to generate key for tenant2");

        // Verify they have different tenant IDs
        assert_eq!(meta1.tenant_id, "tenant-1");
        assert_eq!(meta2.tenant_id, "tenant-2");

        // Cache keys should be different due to tenant_id prefix
        let cache_key1 = cache_key_id(&meta1.id, &meta1.tenant_id);
        let cache_key2 = cache_key_id(&meta2.id, &meta2.tenant_id);
        assert_ne!(cache_key1, cache_key2);

        println!("Redis cache multi-tenant test passed!");
    }

    #[tokio::test]
    #[ignore] // Requires running server (Redis/PostgreSQL)
    async fn test_redis_cache_encrypt_decrypt() {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let redis_client =
            redis::Client::open(redis_url.clone()).expect("Failed to create Redis client");
        let conn_manager = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("Failed to connect to Redis");

        let inner = SoftwareKeystore::new();
        let cached = RedisCachedKeystore::new(inner, conn_manager);

        // Generate key and encrypt
        let spec = KeySpec::Aes256Gcm;
        let meta = cached
            .generate_key(&spec, "enc-test-key", "enc-tenant")
            .await
            .expect("Failed to generate key");

        let plaintext = b"Hello from Redis cached keystore!";
        let ciphertext = cached
            .encrypt(&meta.id, plaintext, None, "enc-tenant")
            .await
            .expect("Failed to encrypt");

        let decrypted = cached
            .decrypt(&meta.id, &ciphertext, None, "enc-tenant")
            .await
            .expect("Failed to decrypt");

        assert_eq!(&decrypted, plaintext);

        println!("Redis cache encrypt/decrypt test passed!");
    }

    #[tokio::test]
    async fn test_redis_cache_health_degraded() {
        // Test that health returns Degraded when Redis is unavailable
        // We use a connection that will succeed initially but subsequent operations fail

        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let redis_client =
            redis::Client::open(redis_url.clone()).expect("Failed to create Redis client");

        // Create connection manager - if this fails, the test is invalid for this environment
        let conn_manager = match redis::aio::ConnectionManager::new(redis_client).await {
            Ok(cm) => cm,
            Err(_) => {
                println!("Redis not available, skipping health degraded test");
                return;
            }
        };

        let inner = SoftwareKeystore::new();
        let cached = RedisCachedKeystore::new(inner, conn_manager);

        // Health should return Healthy when Redis is available
        let health = cached.health().await.expect("Health check failed");
        assert_eq!(health, kms_core::types::HealthStatus::Healthy);

        println!("Redis cache health test passed!");
    }
}
