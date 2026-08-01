//! Fault injection testing utilities for KMS
//!
//! Provides chaos testing capabilities to verify system resilience
//! when dependencies fail or behave unexpectedly.

use std::sync::Arc;

/// Fault injection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMode {
    /// No fault injection
    Disabled,
    /// Fail the operation
    Fail,
    /// Slow down the operation
    Delay(u64),
    /// Return corrupted data
    Corrupt,
}

/// Configuration for fault injection
#[derive(Debug, Clone)]
pub struct FaultConfig {
    pub mode: FaultMode,
    pub probability: f32, // 0.0 to 1.0
    pub enabled: bool,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            mode: FaultMode::Disabled,
            probability: 1.0,
            enabled: false,
        }
    }
}

impl FaultConfig {
    pub fn new(mode: FaultMode, probability: f32) -> Self {
        Self {
            mode,
            probability: probability.clamp(0.0, 1.0),
            enabled: true,
        }
    }

    pub fn fail(probability: f32) -> Self {
        Self::new(FaultMode::Fail, probability)
    }

    pub fn delay(millis: u64, probability: f32) -> Self {
        Self::new(FaultMode::Delay(millis), probability)
    }

    pub fn corrupt(probability: f32) -> Self {
        Self::new(FaultMode::Corrupt, probability)
    }

    pub fn disabled() -> Self {
        Self::default()
    }
}

/// Thread-safe fault injector
#[derive(Debug, Clone)]
pub struct FaultInjector {
    config: Arc<parking_lot::RwLock<FaultConfig>>,
}

impl FaultInjector {
    pub fn new() -> Self {
        Self {
            config: Arc::new(parking_lot::RwLock::new(FaultConfig::default())),
        }
    }

    pub fn configure(&self, config: FaultConfig) {
        let mut cfg = self.config.write();
        *cfg = config;
    }

    pub fn get_config(&self) -> FaultConfig {
        self.config.read().clone()
    }

    pub fn should_fault(&self) -> bool {
        let config = self.config.read();
        if config.enabled && config.probability > 0.0 {
            return rand::random::<f32>() < config.probability;
        }
        false
    }

    pub async fn apply_fault<T>(&self) -> Result<T, FaultError> {
        if !self.should_fault() {
            return Err(FaultError::NotFaulted);
        }

        let config = self.get_config();
        match config.mode {
            FaultMode::Disabled => Err(FaultError::NotFaulted),
            FaultMode::Fail => Err(FaultError::InjectedFailure),
            FaultMode::Delay(ms) => {
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                Err(FaultError::NotFaulted) // Delay doesn't cause error
            }
            FaultMode::Corrupt => Err(FaultError::DataCorrupted),
        }
    }
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can be injected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultError {
    /// No fault was triggered
    NotFaulted,
    /// Injected failure (operation fails)
    InjectedFailure,
    /// Data corruption detected
    DataCorrupted,
    /// Connection lost
    ConnectionLost,
    /// Timeout occurred
    Timeout,
}

impl std::fmt::Display for FaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FaultError::NotFaulted => write!(f, "no fault injected"),
            FaultError::InjectedFailure => write!(f, "injected failure"),
            FaultError::DataCorrupted => write!(f, "data corrupted"),
            FaultError::ConnectionLost => write!(f, "connection lost"),
            FaultError::Timeout => write!(f, "timeout"),
        }
    }
}

impl std::error::Error for FaultError {}

/// Test helpers for chaos testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_config_disabled() {
        let config = FaultConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_fault_config_fail() {
        let config = FaultConfig::fail(0.5);
        assert!(config.enabled);
        assert!(matches!(config.mode, FaultMode::Fail));
        assert_eq!(config.probability, 0.5);
    }

    #[test]
    fn test_fault_config_delay() {
        let config = FaultConfig::delay(100, 0.3);
        assert!(config.enabled);
        assert!(matches!(config.mode, FaultMode::Delay(100)));
        assert_eq!(config.probability, 0.3);
    }

    #[test]
    fn test_fault_config_probability_clamp() {
        // Test that probability is clamped to 0.0-1.0
        let config = FaultConfig::new(FaultMode::Fail, 1.5);
        assert_eq!(config.probability, 1.0);

        let config = FaultConfig::new(FaultMode::Fail, -0.5);
        assert_eq!(config.probability, 0.0);
    }

    #[test]
    fn test_fault_injector_default_disabled() {
        let injector = FaultInjector::new();
        assert!(!injector.should_fault());
    }

    #[test]
    fn test_fault_injector_enabled() {
        let injector = FaultInjector::new();
        injector.configure(FaultConfig::fail(1.0)); // 100% probability

        // With 100% probability, should always fault
        // (but actual behavior depends on RNG, so this is probabilistic)
        let results: Vec<bool> = (0..100).map(|_| injector.should_fault()).collect();
        // Most should be true with 100% probability
        let true_count = results.iter().filter(|&&b| b).count();
        assert!(
            true_count > 90,
            "Expected >90% faults with 100% probability, got {}",
            true_count
        );
    }

    #[test]
    fn test_fault_error_display() {
        assert_eq!(FaultError::InjectedFailure.to_string(), "injected failure");
        assert_eq!(FaultError::DataCorrupted.to_string(), "data corrupted");
    }
}
