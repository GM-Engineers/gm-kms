//! Envelope Encryption - DEK/KEK两层加密架构
//!
//! 文档参考: docs/wiki/envelope-encryption.md
//!
//! # 安全性说明
//!
//! 本模块使用 GM/SM3 HMAC_DRBG (符合 GM/T 0103-2012, GM/T 0105-2012) 生成随机数，
//! 而非使用 ring 的 SystemRandom，确保符合国密标准。

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::csprng::{generate_dek as gm_generate_dek, generate_nonce as gm_generate_nonce};

/// Envelope加密结构 - 包含加密的DEK和密文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// 使用KEK加密后的DEK (base64)
    pub wrapped_dek: String,
    /// DEK的nonce (base64)
    pub dek_nonce: String,
    /// 使用DEK加密的原始数据
    pub ciphertext: String,
    /// 数据加密使用的nonce (base64)
    pub data_nonce: String,
    /// 数据完整性校验码 (base64)
    pub tag: String,
    /// KEK的版本号
    pub kek_version: u32,
}

impl Envelope {
    /// 创建新的信封加密结果
    pub fn new(
        wrapped_dek: Vec<u8>,
        dek_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        data_nonce: Vec<u8>,
        tag: Vec<u8>,
        kek_version: u32,
    ) -> Self {
        Self {
            wrapped_dek: STANDARD.encode(&wrapped_dek),
            dek_nonce: STANDARD.encode(&dek_nonce),
            ciphertext: STANDARD.encode(&ciphertext),
            data_nonce: STANDARD.encode(&data_nonce),
            tag: STANDARD.encode(&tag),
            kek_version,
        }
    }
}

/// DEK信息 - 用于存储在信封中的加密DEK元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DekInfo {
    /// DEK的版本号
    pub version: u32,
    /// DEK创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// 关联的KEK ID
    pub kek_id: String,
    /// DEK是否已轮换
    pub rotated: bool,
}

/// Envelope加密配置
#[derive(Debug, Clone)]
pub struct EnvelopeConfig {
    /// DEK长度(字节) - 默认32字节用于AES-256
    pub dek_length: usize,
    /// 是否启用DEK缓存
    pub cache_dek: bool,
}

impl Default for EnvelopeConfig {
    fn default() -> Self {
        Self {
            dek_length: 32,
            cache_dek: false,
        }
    }
}

/// 生成随机DEK (Data Encryption Key)
///
/// 使用 GM/SM3 HMAC_DRBG 符合国密标准
pub fn generate_dek(length: usize) -> Vec<u8> {
    gm_generate_dek(length)
}

/// 生成随机nonce
///
/// 使用 GM/SM3 HMAC_DRBG 符合国密标准
pub fn generate_nonce(length: usize) -> Vec<u8> {
    gm_generate_nonce(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_serialization() {
        let envelope = Envelope::new(
            vec![1, 2, 3, 4],
            vec![5, 6],
            b"hello world".to_vec(),
            vec![7, 8],
            vec![9, 10, 11, 12],
            1,
        );

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("wrapped_dek"));
        assert!(json.contains("ciphertext"));

        let deserialized: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope.wrapped_dek, deserialized.wrapped_dek);
    }

    #[test]
    fn test_generate_dek() {
        let dek1 = generate_dek(32);
        let dek2 = generate_dek(32);
        assert_eq!(dek1.len(), 32);
        assert_eq!(dek2.len(), 32);
        assert_ne!(dek1, dek2); // Should be random
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce(12);
        assert_eq!(nonce.len(), 12);
    }

    /// Test Envelope field values are base64-encoded
    #[test]
    fn test_envelope_base64_encoding() {
        let raw_dek = vec![0xAA; 32];
        let raw_nonce = vec![0xBB; 12];
        let raw_ciphertext = b"secret data".to_vec();
        let raw_data_nonce = vec![0xCC; 12];
        let raw_tag = vec![0xDD; 16];

        let envelope = Envelope::new(
            raw_dek.clone(),
            raw_nonce.clone(),
            raw_ciphertext.clone(),
            raw_data_nonce.clone(),
            raw_tag.clone(),
            3,
        );

        // Verify base64 encoding
        assert_eq!(
            envelope.wrapped_dek,
            STANDARD.encode(&raw_dek)
        );
        assert_eq!(
            envelope.dek_nonce,
            STANDARD.encode(&raw_nonce)
        );
        assert_eq!(
            envelope.ciphertext,
            STANDARD.encode(&raw_ciphertext)
        );
        assert_eq!(
            envelope.data_nonce,
            STANDARD.encode(&raw_data_nonce)
        );
        assert_eq!(
            envelope.tag,
            STANDARD.encode(&raw_tag)
        );
        assert_eq!(envelope.kek_version, 3);
    }

    /// Test EnvelopeConfig default
    #[test]
    fn test_envelope_config_default() {
        let config = EnvelopeConfig::default();
        assert_eq!(config.dek_length, 32);
        assert!(!config.cache_dek);
    }

    /// Test DekInfo fields
    #[test]
    fn test_dek_info() {
        let info = DekInfo {
            version: 2,
            created_at: chrono::Utc::now(),
            kek_id: "kek-001".to_string(),
            rotated: false,
        };
        assert_eq!(info.version, 2);
        assert_eq!(info.kek_id, "kek-001");
        assert!(!info.rotated);
    }

    /// Test generate_dek with different lengths
    #[test]
    fn test_generate_dek_various_lengths() {
        for len in [16, 24, 32, 48, 64] {
            let dek = generate_dek(len);
            assert_eq!(dek.len(), len);
        }
    }

    /// Test generate_nonce with various lengths
    #[test]
    fn test_generate_nonce_various_lengths() {
        for len in [8, 12, 16, 24, 32] {
            let nonce = generate_nonce(len);
            assert_eq!(nonce.len(), len);
        }
    }
}
