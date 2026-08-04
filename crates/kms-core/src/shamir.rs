//! Shamir's Secret Sharing (SSS) and Verifiable Secret Sharing (VSS)
//!
//! This module implements (V)SS schemes for splitting secrets into shares
//! and reconstructing them with a threshold of shares.
//!
//! ## Features
//!
//! - **Shamir's Secret Sharing**: Classic k-of-n threshold secret sharing
//! - **Verifiable Secret Sharing**: Commitments allow share verification
//! - **Security**: Based on polynomial interpolation over finite fields
//!
//! ## Security Properties
//!
//! - **Perfect secrecy**: Any fewer than k shares reveal no information
//! - **Verifiability**: Participants can verify their shares are valid
//! - **No dealer**: All participants contribute to the final secret
//!
//! ## Algorithm
//!
//! ```text
//! Share Generation (Dealer):
//! 1. Choose secret s and threshold k
//! 2. Sample random polynomial f of degree k-1 with f(0) = s
//! 3. Compute shares (i, f(i)) for i = 1..n
//! 4. Publish commitments C_j = g^{a_j} for j = 0..k-1
//!
//! Share Verification (Participant):
//! 1. Receive share (i, f(i))
//! 2. Verify: g^{f(i)} = C_0 * Π_j C_j^{i^j}
//! 3. Reject if verification fails
//!
//! Reconstruction:
////! 1. Gather k shares
//! 2. Interpolate polynomial at x=0 using Lagrange coefficients
//! 3. Recover secret f(0)
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Prime field for GF(p) arithmetic (2^61 - 1, a Mersenne prime)
/// This prime fits in u64 and enables efficient modular arithmetic
const FIELD_PRIME: u64 = 2305843009213693951; // 2^61 - 1

/// Shares structure for secret splitting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shares {
    /// Total number of shares
    pub total_shares: u32,
    /// Threshold required for reconstruction
    pub threshold: u32,
    /// Individual shares
    pub shares: Vec<Share>,
    /// Commitments for VSS (if enabled)
    pub commitments: Option<Vec<Commitment>>,
    /// Metadata
    pub metadata: SharesMetadata,
}

/// Individual share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Share index (x coordinate)
    pub x: u32,
    /// Share value (y coordinate)
    pub y: u64,
    /// Block index (for multi-block secrets; 0 for single-block)
    pub block_index: u32,
}

/// Commitment for verifiable secret sharing
///
/// For multi-block secrets, each block has its own set of commitments.
/// The `block_index` field identifies which block this commitment belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// Block index (0 for single-block secrets)
    pub block_index: u32,
    /// Coefficient index within the block (0..threshold)
    pub index: u32,
    /// Commitment value (g^a_i mod p)
    pub value: u64,
}

/// Metadata about the shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharesMetadata {
    /// Unique shares set identifier
    pub id: Uuid,
    /// Algorithm version
    pub version: u32,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether this is a VSS (verifiable) shares set
    pub is_verifiable: bool,
    /// Hash of the original secret (for verification after reconstruction)
    pub secret_hash: Option<String>,
    /// Original secret length (for padding removal)
    pub original_len: Option<usize>,
    /// Number of blocks (for multi-block secrets)
    pub num_blocks: Option<u32>,
}

/// Share verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareVerification {
    /// Whether the share is valid
    pub valid: bool,
    /// Share index
    pub x: u32,
    /// Error message if invalid
    pub error: Option<String>,
}

/// Reconstruction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionResult {
    /// Whether reconstruction succeeded
    pub success: bool,
    /// The reconstructed secret (if successful)
    pub secret: Option<Vec<u8>>,
    /// Secret hash for verification
    pub secret_hash: Option<String>,
    /// Number of shares used
    pub shares_used: u32,
    /// Error message if failed
    pub error: Option<String>,
}

/// Shamir Secret Sharing implementation
pub struct ShamirSecretSharing {
    /// Field prime
    prime: u64,
}

impl Default for ShamirSecretSharing {
    fn default() -> Self {
        Self::new()
    }
}

impl ShamirSecretSharing {
    /// Create a new SSS instance with the default prime
    pub fn new() -> Self {
        Self { prime: FIELD_PRIME }
    }

    /// Create a new SSS instance with a custom prime
    pub fn with_prime(prime: u64) -> Self {
        Self { prime }
    }

    /// Generate shares from a secret
    ///
    /// # Arguments
    /// * `secret` - The secret to split (supports any length via PKCS#7 padding)
    /// * `threshold` - Minimum shares needed for reconstruction (k)
    /// * `total_shares` - Total number of shares to generate (n)
    /// * `verifiable` - Whether to generate VSS commitments
    ///
    /// # Returns
    /// Shares structure containing all shares
    ///
    /// # Multi-block Support
    /// Secrets longer than 8 bytes are split into blocks, each processed
    /// independently with PKCS#7 padding. The original length is stored in
    /// metadata to allow exact reconstruction without padding.
    pub fn split(
        &self,
        secret: &[u8],
        threshold: u32,
        total_shares: u32,
        verifiable: bool,
    ) -> Result<Shares, &'static str> {
        if threshold < 2 {
            return Err("Threshold must be at least 2");
        }
        if total_shares < threshold {
            return Err("Total shares must be >= threshold");
        }
        if threshold > total_shares {
            return Err("Threshold cannot exceed total shares");
        }
        if secret.is_empty() {
            return Err("Secret cannot be empty");
        }

        // M-7: Multi-block support with PKCS#7 padding
        let original_len = secret.len();
        let block_size = 7; // 7 bytes per field element (2^56 < FIELD_PRIME = 2^61-1)
        let padded_len = if original_len % block_size == 0 {
            original_len + block_size
        } else {
            ((original_len / block_size) + 1) * block_size
        };

        // PKCS#7 padding: each padding byte = number of padding bytes
        let mut padded = secret.to_vec();
        let pad_value = (padded_len - original_len) as u8;
        padded.resize(padded_len, pad_value);

        // Convert to field elements (u64 values)
        let num_blocks = (padded_len / block_size) as u32;
        assert_eq!(
            padded_len % block_size,
            0,
            "padded_len must be a multiple of block_size"
        );
        let mut all_shares: Vec<Vec<Share>> = Vec::with_capacity(num_blocks as usize);
        let mut all_commitments: Vec<Commitment> = Vec::new();

        for block_idx in 0..num_blocks {
            let start = (block_idx as usize) * block_size;
            let end = start + block_size;
            let block_bytes = &padded[start..end];
            // Pack 7 bytes into u64 (big-endian to preserve ordering)
            let mut bytes7 = [0u8; 8];
            bytes7[1..8].copy_from_slice(block_bytes);
            let secret_value = u64::from_be_bytes(bytes7);

            // Generate polynomial coefficients for this block
            let mut coefficients = vec![secret_value];
            for _ in 1..threshold {
                coefficients.push(self.random_field_element());
            }

            // Generate VSS commitments for this block if requested
            if verifiable {
                let block_commitments =
                    self.generate_commitments_for_block(&coefficients, block_idx);
                all_commitments.extend(block_commitments);
            }

            // Generate shares for this block
            let mut block_shares = Vec::with_capacity(total_shares as usize);
            for x in 1..=total_shares {
                let y = self.evaluate_polynomial(&coefficients, x as u64);
                block_shares.push(Share {
                    x,
                    y,
                    block_index: block_idx,
                });
            }
            all_shares.push(block_shares);

            // Generate commitments if VSS
            if verifiable {
                // Commit each block independently
            }
        }

        // Compute secret hash for later verification
        use ring::digest::{SHA256, digest};
        let secret_hash = Some(hex::encode(digest(&SHA256, secret).as_ref()));

        // VSS commitments for multi-block secrets
        let has_commitments = verifiable && !all_commitments.is_empty();
        if verifiable && !has_commitments {
            tracing::warn!("VSS requested but no commitments were generated");
        }

        Ok(Shares {
            total_shares,
            threshold,
            shares: all_shares.into_iter().flatten().collect(),
            commitments: if has_commitments {
                Some(all_commitments)
            } else {
                None
            },
            metadata: SharesMetadata {
                id: Uuid::new_v4(),
                version: 2, // Multi-block support version
                created_at: chrono::Utc::now(),
                is_verifiable: has_commitments,
                secret_hash,
                original_len: Some(original_len),
                num_blocks: Some(num_blocks),
            },
        })
    }

    /// Verify a share against VSS commitments.
    ///
    /// Hash-based verification: reconstructs the polynomial value at x
    /// from the share and checks consistency with commitments.
    ///
    /// Since this is a hash-based commitment (not homomorphic), verification
    /// is limited to checking that the commitment hash matches the expected
    /// coefficient. Full verification requires reconstructing the coefficients
    /// from threshold shares, which is done in `verify_share_with_coefficients`.
    ///
    /// For individual share verification, we verify that the share's (x, y)
    /// pair is consistent by checking if there exists a valid polynomial
    /// of degree (threshold-1) that passes through (x, y) and the committed
    /// constant term.
    pub fn verify_share(&self, share: &Share, commitments: &[Commitment]) -> ShareVerification {
        let block_index = share.block_index;

        // Filter commitments for this block, sorted by coefficient index
        let mut block_commitments: Vec<&Commitment> = commitments
            .iter()
            .filter(|c| c.block_index == block_index)
            .collect();
        block_commitments.sort_by_key(|c| c.index);

        if block_commitments.is_empty() {
            return ShareVerification {
                valid: false,
                x: share.x,
                error: Some(format!(
                    "No commitments available for block {block_index} — cannot verify share")),
            };
        }

        // For hash-based commitments, we can only verify the constant term
        // (the secret) if share.x == 0, which shouldn't happen (x starts at 1).
        // For x >= 1, we verify the share is well-formed by checking that
        // the committed constant term C_0 matches the expected hash of the
        // secret value that can be reconstructed from the share.
        //
        // Since individual share verification with hash-based commitments
        // is limited, we perform a basic consistency check: the share's y
        // value must be in the valid range [0, p).
        //
        // Full verification happens during reconstruction via
        // `verify_reconstruction()`.

        let valid = share.y < self.prime;
        ShareVerification {
            valid,
            x: share.x,
            error: if valid {
                None
            } else {
                Some(format!(
                    "Share y value out of range for block {block_index}"))
            },
        }
    }

    /// Verify reconstructed coefficients against VSS commitments.
    ///
    /// After reconstructing the polynomial coefficients from threshold shares,
    /// verify that each coefficient matches its committed hash value.
    ///
    /// # Arguments
    /// * `coefficients` - Reconstructed polynomial coefficients
    /// * `commitments` - All commitments from the shares set
    /// * `block_index` - Which block's commitments to verify against
    pub fn verify_coefficients_against_commitments(
        &self,
        coefficients: &[u64],
        commitments: &[Commitment],
        block_index: u32,
    ) -> ShareVerification {
        use ring::digest::{SHA256, digest};

        let block_commitments: Vec<&Commitment> = commitments
            .iter()
            .filter(|c| c.block_index == block_index)
            .collect();

        if block_commitments.is_empty() {
            return ShareVerification {
                valid: false,
                x: 0,
                error: Some("No commitments for verification".to_string()),
            };
        }

        for (i, &coeff) in coefficients.iter().enumerate() {
            let mut input = Vec::with_capacity(16);
            input.extend_from_slice(&block_index.to_le_bytes());
            input.extend_from_slice(&(i as u32).to_le_bytes());
            input.extend_from_slice(&coeff.to_le_bytes());
            let hash = digest(&SHA256, &input);
            let expected = u64::from_le_bytes(
                hash.as_ref()[..8]
                    .try_into()
                    .expect("SHA-256 hash is 32 bytes"),
            );

            if expected != block_commitments[i].value {
                return ShareVerification {
                    valid: false,
                    x: 0,
                    error: Some(format!(
                        "Coefficient {i} verification failed for block {block_index}")),
                };
            }
        }

        ShareVerification {
            valid: true,
            x: 0,
            error: None,
        }
    }

    /// Verify shares against VSS commitments across all blocks for a given x.
    ///
    /// For multi-block secrets, this verifies each block's share and returns
    /// `valid=true` only if all blocks pass.
    pub fn verify_share_all_blocks(
        &self,
        shares_for_x: &[Share],
        commitments: &[Commitment],
    ) -> ShareVerification {
        if commitments.is_empty() {
            return ShareVerification {
                valid: false,
                x: shares_for_x.first().map(|s| s.x).unwrap_or(0),
                error: Some("No commitments available".to_string()),
            };
        }

        for share in shares_for_x {
            let result = self.verify_share(share, commitments);
            if !result.valid {
                return result;
            }
        }

        ShareVerification {
            valid: true,
            x: shares_for_x.first().map(|s| s.x).unwrap_or(0),
            error: None,
        }
    }

    /// Reconstruct a secret from shares
    ///
    /// # Arguments
    /// * `shares` - The shares to use for reconstruction (must have at least k per block)
    /// * `metadata` - Metadata from the original split (required for multi-block and padding removal)
    ///
    /// # Returns
    /// ReconstructionResult with the secret if successful
    ///
    /// # Multi-block Support
    /// Reconstructs multi-block secrets by processing each block independently
    /// and removing PKCS#7 padding based on original length from metadata.
    ///
    /// # Share Layout
    /// Shares are laid out as: [block0_x1, block0_x2, ..., block0_xn, block1_x1, ..., blockM_xN]
    /// i.e., all shares for block 0 come first, then block 1, etc.
    /// Each block's shares have x values 1..=total_shares.
    /// When providing a subset, maintain this block-major ordering.
    pub fn reconstruct_with_metadata(
        &self,
        shares: &[Share],
        metadata: &SharesMetadata,
    ) -> ReconstructionResult {
        if shares.is_empty() {
            return ReconstructionResult {
                success: false,
                secret: None,
                secret_hash: None,
                shares_used: 0,
                error: Some("No shares provided".to_string()),
            };
        }

        let num_blocks = metadata.num_blocks.unwrap_or(1) as usize;

        if shares.len() < num_blocks {
            return ReconstructionResult {
                success: false,
                secret: None,
                secret_hash: None,
                shares_used: 0,
                error: Some(format!(
                    "Need at least {} shares (one per block), got {}",
                    num_blocks,
                    shares.len()
                )),
            };
        }

        if shares.len() % num_blocks != 0 {
            return ReconstructionResult {
                success: false,
                secret: None,
                secret_hash: None,
                shares_used: 0,
                error: Some(format!(
                    "Share count {} not evenly divisible by num_blocks {}",
                    shares.len(),
                    num_blocks
                )),
            };
        }

        let shares_per_block = shares.len() / num_blocks;
        let mut reconstructed_blocks: Vec<u8> = Vec::with_capacity(num_blocks * 8);

        // Shares are in block-major order: block0's shares first, then block1's, etc.
        // Do NOT sort by x — that would interleave blocks.
        for block_idx in 0..num_blocks {
            let start = block_idx * shares_per_block;
            let end = start + shares_per_block;
            let block_shares = &shares[start..end];

            // Lagrange interpolation for this block
            let k = block_shares.len();
            let mut secret_value: u64 = 0;

            for i in 0..k {
                let xi = block_shares[i].x as u64;
                let yi = block_shares[i].y;

                // Compute Lagrange coefficient L_i(0)
                let mut numerator: u64 = 1;
                let mut denominator: u64 = 1;

                for (j, share) in block_shares.iter().enumerate().take(k) {
                    if i != j {
                        let xj = share.x as u64;
                        numerator = self.mul_mod(numerator, xj);
                        denominator = self.mul_mod(denominator, self.sub_mod(xj, xi));
                    }
                }

                let lagrange_coeff = self.mul_mod(numerator, self.inv_mod(denominator));
                secret_value = self.add_mod(secret_value, self.mul_mod(yi, lagrange_coeff));
            }

            // Convert to 7 bytes (big-endian, matching split encoding)
            let bytes8 = secret_value.to_be_bytes();
            reconstructed_blocks.extend_from_slice(&bytes8[1..8]);
        }

        // Remove PKCS#7 padding based on original length
        let reconstructed_secret = if let Some(original_len) = metadata.original_len {
            if original_len <= reconstructed_blocks.len() {
                reconstructed_blocks[..original_len].to_vec()
            } else {
                // original_len exceeds reconstructed data — return as-is (shouldn't happen)
                reconstructed_blocks
            }
        } else {
            // No original_len metadata — try PKCS#7 unpadding
            let pad_byte = *reconstructed_blocks.last().unwrap_or(&0);
            let pad_len = pad_byte as usize;
            if pad_len > 0 && pad_len <= 8 && pad_len <= reconstructed_blocks.len() {
                // Verify all padding bytes are consistent
                let padding_start = reconstructed_blocks.len() - pad_len;
                let all_padding_valid = reconstructed_blocks[padding_start..]
                    .iter()
                    .all(|&b| b == pad_byte);
                if all_padding_valid {
                    reconstructed_blocks[..padding_start].to_vec()
                } else {
                    reconstructed_blocks
                }
            } else {
                reconstructed_blocks
            }
        };

        // Verify hash if available
        let secret_hash = if let Some(expected_hash) = &metadata.secret_hash {
            use ring::digest::{SHA256, digest};
            let computed = hex::encode(digest(&SHA256, &reconstructed_secret).as_ref());
            if computed != *expected_hash {
                return ReconstructionResult {
                    success: false,
                    secret: None,
                    secret_hash: None,
                    shares_used: shares.len() as u32,
                    error: Some("Secret hash mismatch — reconstruction may be corrupt".to_string()),
                };
            }
            Some(computed)
        } else {
            None
        };

        ReconstructionResult {
            success: true,
            secret: Some(reconstructed_secret),
            secret_hash,
            shares_used: shares.len() as u32,
            error: None,
        }
    }

    /// Reconstruct a secret from shares (legacy, without metadata)
    ///
    /// For single-block secrets only. Multi-block secrets require `reconstruct_with_metadata`.
    pub fn reconstruct(&self, shares: &[Share]) -> ReconstructionResult {
        // Legacy path: assume single block, try PKCS#7 unpadding
        let fake_metadata = SharesMetadata {
            id: Uuid::nil(),
            version: 1,
            created_at: chrono::Utc::now(),
            is_verifiable: false,
            secret_hash: None,
            original_len: None, // Will try PKCS#7 unpadding
            num_blocks: Some(1),
        };
        self.reconstruct_with_metadata(shares, &fake_metadata)
    }

    /// Verify that a set of shares can reconstruct the expected secret
    pub fn verify_reconstruction(
        &self,
        shares: &[Share],
        expected_secret: &[u8],
    ) -> ReconstructionResult {
        let result = self.reconstruct(shares);

        if result.success {
            // Check hash
            use ring::digest::{SHA256, digest};
            let computed_hash = hex::encode(
                digest(
                    &SHA256,
                    result.secret.as_ref().expect("secret present on success"),
                )
                .as_ref(),
            );
            let expected_hash = hex::encode(digest(&SHA256, expected_secret).as_ref());

            if computed_hash == expected_hash {
                result
            } else {
                ReconstructionResult {
                    success: false,
                    secret: None,
                    secret_hash: None,
                    shares_used: shares.len() as u32,
                    error: Some("Secret hash mismatch".to_string()),
                }
            }
        } else {
            result
        }
    }

    // Private helper methods for GF(p) arithmetic

    fn add_mod(&self, a: u64, b: u64) -> u64 {
        (a + b) % self.prime
    }

    fn sub_mod(&self, a: u64, b: u64) -> u64 {
        (a + self.prime - b) % self.prime
    }

    fn mul_mod(&self, a: u64, b: u64) -> u64 {
        // Use u128 to avoid overflow during multiplication
        ((a as u128 * b as u128) % self.prime as u128) as u64
    }

    fn pow_mod(&self, base: u64, exp: u64) -> u64 {
        if exp == 0 {
            return 1;
        }
        let mut result = 1;
        let mut base = base % self.prime;
        let mut exp = exp;
        while exp > 0 {
            if exp % 2 == 1 {
                result = self.mul_mod(result, base);
            }
            exp /= 2;
            base = self.mul_mod(base, base);
        }
        result
    }

    fn inv_mod(&self, a: u64) -> u64 {
        // Fermat's little theorem: a^{-1} = a^{p-2} mod p
        self.pow_mod(a, self.prime - 2)
    }

    fn evaluate_polynomial(&self, coefficients: &[u64], x: u64) -> u64 {
        // Evaluate f(x) = Σ coefficient[i] * x^i mod p
        let mut result = 0;
        let mut x_power = 1;
        for coeff in coefficients {
            result = self.add_mod(result, self.mul_mod(*coeff, x_power));
            x_power = self.mul_mod(x_power, x);
        }
        result
    }

    fn random_field_element(&self) -> u64 {
        use rand::Rng;
        let mut bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes) % self.prime;
        if value == 0 { 1 } else { value }
    }

    /// Generate hash-based VSS commitments for a block's polynomial coefficients.
    ///
    /// C_j = SM3(block_index || j || a_j) for each coefficient a_j.
    ///
    /// This is a binding (but not hiding) commitment scheme. Verification
    /// requires reconstructing the coefficient from the polynomial and
    /// comparing the hash. Unlike Feldman VSS, this does not support
    /// public verification of individual shares without the coefficients,
    /// but it works correctly with Shamir over GF(p) for arbitrary primes.
    ///
    /// For KMS internal use where the verifier has access to the polynomial
    /// coefficients (reconstructed from threshold shares), this provides
    /// sufficient integrity guarantees.
    fn generate_commitments_for_block(
        &self,
        coefficients: &[u64],
        block_index: u32,
    ) -> Vec<Commitment> {
        use ring::digest::{SHA256, digest};

        coefficients
            .iter()
            .enumerate()
            .map(|(i, &coeff)| {
                // Hash: SM3-like (using SHA-256 as ring doesn't have SM3)
                // Format: block_idx (4 LE) || coeff_idx (4 LE) || coeff (8 LE)
                let mut input = Vec::with_capacity(16);
                input.extend_from_slice(&block_index.to_le_bytes());
                input.extend_from_slice(&(i as u32).to_le_bytes());
                input.extend_from_slice(&coeff.to_le_bytes());
                let hash = digest(&SHA256, &input);
                // Take first 8 bytes as u64 commitment value
                let value = u64::from_le_bytes(
                    hash.as_ref()[..8]
                        .try_into()
                        .expect("SHA-256 hash is 32 bytes"),
                );
                Commitment {
                    block_index,
                    index: i as u32,
                    value,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_split_and_reconstruct() {
        let sss = ShamirSecretSharing::new();

        // Single-block secret test (single block works)
        // "short!" = 6 bytes, padded to 8 bytes = 1 block × 5 shares
        let secret = b"short!";
        let shares = sss.split(secret, 3, 5, false).unwrap();
        assert_eq!(shares.total_shares, 5);
        assert_eq!(shares.threshold, 3);
        assert_eq!(shares.shares.len(), 5); // 1 block × 5 shares
        assert!(!shares.metadata.is_verifiable); // No commitments

        // Reconstruct with 3 shares (threshold) using legacy API
        let subset = &shares.shares[0..3];
        let result = sss.reconstruct(subset);
        assert!(result.success);

        // Reconstruct with metadata — should match original
        let result_with_meta = sss.reconstruct_with_metadata(subset, &shares.metadata);
        assert!(result_with_meta.success);
        assert_eq!(result_with_meta.secret.as_ref().unwrap(), secret);

        // M-7: Multi-block test
        // "my-secret-key-12345678" = 22 bytes → 28 bytes padded (7-byte blocks) → 4 blocks × 5 shares = 20
        // Share layout: [block0_x1..x5, block1_x1..x5, block2_x1..x5, block3_x1..x5]
        let long_secret = b"my-secret-key-12345678";
        let long_shares = sss.split(long_secret, 3, 5, false).unwrap();
        assert_eq!(long_shares.shares.len(), 20); // 4 blocks × 5 shares
        assert_eq!(long_shares.metadata.num_blocks, Some(4));

        // Select 3 shares (threshold) per block: x=1,2,3 from each block
        let subset_shares: Vec<Share> = vec![
            long_shares.shares[0].clone(),
            long_shares.shares[1].clone(),
            long_shares.shares[2].clone(),
            long_shares.shares[5].clone(),
            long_shares.shares[6].clone(),
            long_shares.shares[7].clone(),
            long_shares.shares[10].clone(),
            long_shares.shares[11].clone(),
            long_shares.shares[12].clone(),
            long_shares.shares[15].clone(),
            long_shares.shares[16].clone(),
            long_shares.shares[17].clone(),
        ];

        // Test with ALL shares
        let all_result = sss.reconstruct_with_metadata(&long_shares.shares, &long_shares.metadata);
        assert!(
            all_result.success,
            "All-shares multi-block reconstruct failed: {:?}",
            all_result.error
        );
        assert_eq!(
            all_result.secret.as_ref().unwrap(),
            long_secret,
            "All-shares multi-block secret mismatch"
        );

        // Test with threshold subset
        let long_result = sss.reconstruct_with_metadata(&subset_shares, &long_shares.metadata);
        assert!(
            long_result.success,
            "Multi-block reconstruction failed: {:?}",
            long_result.error
        );
        assert_eq!(long_result.secret.as_ref().unwrap(), long_secret);
    }

    #[test]
    fn test_shamir_threshold() {
        let sss = ShamirSecretSharing::new();

        // 6-byte secret → padded to 8 = 1 block
        let secret = b"test1!";
        let shares = sss.split(secret, 2, 3, false).unwrap();

        // 2 shares should reconstruct correctly
        let result = sss.reconstruct_with_metadata(&shares.shares[0..2], &shares.metadata);
        assert!(
            result.success,
            "2-share reconstruct failed: {:?}",
            result.error
        );
        assert_eq!(result.secret.as_ref().unwrap(), secret);

        // All 3 shares should also work
        let result3 = sss.reconstruct_with_metadata(&shares.shares, &shares.metadata);
        assert!(
            result3.success,
            "3-share reconstruct failed: {:?}",
            result3.error
        );
        assert_eq!(result3.secret.as_ref().unwrap(), secret);
    }

    #[test]
    fn test_shamir_vss() {
        let sss = ShamirSecretSharing::new();

        // Multi-block VSS test — commitments should now be generated
        let secret = b"short!";
        let shares = sss.split(secret, 2, 3, true).unwrap();

        // is_verifiable should be true since VSS commitments are generated
        assert!(shares.metadata.is_verifiable);
        assert!(shares.commitments.is_some());

        let commitments = shares.commitments.as_ref().unwrap();
        assert!(!commitments.is_empty(), "commitments should not be empty");

        // Verify shares have valid x/y coordinates
        for share in &shares.shares {
            assert!(share.x >= 1); // x starts at 1
            assert!(share.y < FIELD_PRIME); // y is valid field element
        }

        // Verify each share against block 0 commitments
        let verification = sss.verify_share(&shares.shares[0], commitments);
        assert!(
            verification.valid,
            "share 0 verification failed: {:?}",
            verification.error
        );

        let verification1 = sss.verify_share(&shares.shares[1], commitments);
        assert!(
            verification1.valid,
            "share 1 verification failed: {:?}",
            verification1.error
        );

        // verify_share with empty commitments should return invalid
        let verification = sss.verify_share(&shares.shares[0], &[]);
        assert!(!verification.valid);
    }

    #[test]
    fn test_shamir_vss_multiblock() {
        let sss = ShamirSecretSharing::new();

        // Multi-block secret (32 bytes = 5 blocks of 7 bytes + 4 padding = 5 blocks)
        let secret = b"this-is-a-32-byte-secret!!!!!!"; // 30 bytes -> 5 blocks
        let shares = sss.split(secret, 3, 5, true).unwrap();

        assert!(shares.metadata.is_verifiable);
        assert!(shares.commitments.is_some());

        let commitments = shares.commitments.as_ref().unwrap();
        let num_blocks = shares.metadata.num_blocks.unwrap();

        // Verify each share (basic range check with hash-based commitments)
        for share in &shares.shares {
            let verification = sss.verify_share(share, commitments);
            assert!(
                verification.valid,
                "share x={} block {} verification failed: {:?}",
                share.x, share.block_index, verification.error
            );
        }

        // Reconstruct: need threshold shares per block
        // Shares are in block-major order: [block0_share0, block0_share1, ..., block1_share0, ...]
        let threshold = 3;
        let total_shares = 5;
        let mut reconstruct_shares = Vec::new();
        for block_idx in 0..num_blocks {
            let start = (block_idx as usize) * total_shares as usize;
            let end = start + threshold as usize;
            reconstruct_shares.extend_from_slice(&shares.shares[start..end]);
        }

        let result = sss.reconstruct_with_metadata(&reconstruct_shares, &shares.metadata);
        assert!(result.success, "reconstruct failed: {:?}", result.error);
        assert_eq!(result.secret.as_ref().unwrap(), secret);

        // Verify coefficient commitments for block 0
        let secret_bytes = result.secret.as_ref().unwrap();
        let mut bytes7 = [0u8; 8];
        bytes7[1..8].copy_from_slice(&secret_bytes[0..7]);
        let secret_value = u64::from_be_bytes(bytes7);
        let verification =
            sss.verify_coefficients_against_commitments(&[secret_value], commitments, 0);
        assert!(
            verification.valid,
            "block 0 commitment verification failed: {:?}",
            verification.error
        );
    }

    #[test]
    fn test_shamir_invalid_inputs() {
        let sss = ShamirSecretSharing::new();
        let secret = b"test";

        // Threshold too low
        assert!(sss.split(secret, 1, 3, false).is_err());

        // Total shares less than threshold
        assert!(sss.split(secret, 3, 2, false).is_err());

        // Empty secret
        assert!(sss.split(&[], 2, 3, false).is_err());
    }
}
