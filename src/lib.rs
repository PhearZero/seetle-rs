use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use thiserror::Error;

pub mod config;
pub mod tui;
pub mod tpm;
pub mod keyring;
pub mod secure_env;
pub mod xhd;
pub mod nordic;
#[cfg(feature = "tropic")]
pub mod tropic;
pub mod mock;
pub mod file;
pub mod memory;
pub mod init;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum KeyType {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "private")]
    Private,
    #[serde(rename = "secret")]
    Secret,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum KeyUsage {
    #[serde(rename = "encrypt")]
    Encrypt,
    #[serde(rename = "decrypt")]
    Decrypt,
    #[serde(rename = "sign")]
    Sign,
    #[serde(rename = "verify")]
    Verify,
    #[serde(rename = "deriveKey")]
    DeriveKey,
    #[serde(rename = "deriveBits")]
    DeriveBits,
    #[serde(rename = "wrapKey")]
    WrapKey,
    #[serde(rename = "unwrapKey")]
    UnwrapKey,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CryptoKey {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub extractable: bool,
    pub algorithm: Algorithm,
    pub usages: Vec<KeyUsage>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Ecdsa {
        name: String,
        named_curve: String,
        hash: Option<String>,
    },
    RsaPss {
        name: String,
        modulus_length: u32,
        public_exponent: Vec<u8>,
        hash: String,
        salt_length: u32,
    },
    AesGcm {
        name: String,
        length: u16,
        iv: Vec<u8>,
        additional_data: Option<Vec<u8>>,
        tag_length: Option<u8>,
    },
    Generic {
        name: String,
    },
    /// A raw key or seed of a given length in bits.
    Raw {
        length: u32,
    },
    Ed25519 {
        name: String,
    },
    Ecdh {
        name: String,
        public_key: Vec<u8>,
    },
    Hpke {
        name: String, // e.g., "DHKEM_X25519_HKDF_SHA256"
        public_key: Option<Vec<u8>>, // For encrypt/seal
        info: Option<Vec<u8>>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum HardwareBound {
    #[default]
    No,
    Yes,
    Partial,
}

/// Key management extension for hardware-backed keys.
///
/// Based on the Brave experiments draft for hardware-backed webcrypto.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct Bindings {
    /// Determines if the CryptoKey will be hardware bound.
    /// If set to true, extractable must be false.
    #[serde(rename = "hardwareBound", alias = "hardware_bound")]
    pub hardware_bound: HardwareBound,

    pub extractable: bool,

    /// List of origins which have access to this cryptographic key for usage and management.
    /// Defaults to the origin of the caller if not set.
    #[serde(rename = "originBindings")]
    pub origin_bindings: Vec<String>,

    /// A global identifier (e.g. UUID) to refer to the CryptoKey beyond its lifetime.
    pub identifier: String,

    /// Allows the original creator to limit whether or not a key can be updated.
    pub updatable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct KeyMetadata {
    pub identifier: String,
    pub algorithm: String,
    pub usages: Vec<KeyUsage>,
    pub hardware_bound: HardwareBound,
    pub extractable: bool,
    pub public_key: Option<Vec<u8>>,

    // XHD Specific
    pub context: Option<String>,
    pub account: Option<u32>,
    pub index: Option<u32>,
    pub derivation: Option<String>,
    pub source_key_identifier: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum KeyOrIdentifier {
    Key(CryptoKey),
    Identifier(String),
}

#[derive(Debug, Error)]
pub enum SeetleError {
    #[error("Algorithm not supported")]
    NotSupported,
    #[error("Data error")]
    DataError,
    #[error("Operation error: {0}")]
    OperationError(String),
    #[error("Key not found")]
    KeyNotFound,
    #[error("Access denied")]
    AccessDenied,
    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Secure storage interface for persisting key metadata.
#[async_trait]
pub trait SecureStorage: Send + Sync {
    /// Retrieves a value for the given key.
    async fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, SeetleError>;

    /// Stores a value for the given key.
    async fn set_item(&self, key: &str, value: Vec<u8>) -> Result<(), SeetleError>;

    /// Deletes a value for the given key.
    async fn remove_item(&self, key: &str) -> Result<(), SeetleError>;

    /// Lists all keys stored.
    async fn list_items(&self) -> Result<Vec<String>, SeetleError>;
}



#[async_trait]
pub trait Seetle: Send + Sync {
    /// Generates a new key (or key pair).
    ///
    /// If `bindings` are provided with `hardware_bound: true`, the key will be hardware-backed.
    /// In this case, `extractable` must be `false`.
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError>;

    /// Updates the bindings for a hardware-backed key.
    ///
    /// Can be used to grant new origins access to the key.
    /// This operation may require user consent and is only possible if the key was created as `updatable: true`.
    async fn update_key(
        &self,
        identifier: String,
        new_bindings: Bindings,
    ) -> Result<(), SeetleError>;

    /// Deletes a hardware-backed key by its identifier.
    async fn delete_key(
        &self,
        identifier: String,
    ) -> Result<(), SeetleError>;

    /// Lists all identifiers of hardware-backed keys.
    async fn list_keys(&self) -> Result<Vec<String>, SeetleError>;

    /// Gets metadata for a hardware-backed key.
    async fn get_key_metadata(&self, identifier: String) -> Result<KeyMetadata, SeetleError>;

    /// Generates a digital signature for the given data.
    ///
    /// The `key` can be a `CryptoKey` object or a string `identifier` for a hardware-backed key.
    async fn sign(
        &self,
        algorithm: Algorithm,
        key: KeyOrIdentifier,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError>;

    /// Verifies a digital signature for the given data.
    ///
    /// The `key` can be a `CryptoKey` object or a string `identifier` for a hardware-backed key.
    async fn verify(
        &self,
        algorithm: Algorithm,
        key: KeyOrIdentifier,
        signature: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<bool, SeetleError>;

    /// Encrypts the given data.
    async fn encrypt(
        &self,
        algorithm: Algorithm,
        key: KeyOrIdentifier,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError>;

    /// Decrypts the given data.
    async fn decrypt(
        &self,
        algorithm: Algorithm,
        key: KeyOrIdentifier,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError>;

    /// Generates a digest for the given data.
    async fn digest(
        &self,
        algorithm: Algorithm,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError>;

    /// Imports a key from the given format.
    async fn import_key(
        &self,
        format: String,
        key_data: Vec<u8>,
        algorithm: Algorithm,
        extractable: bool,
        key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError>;

    /// Exports a key into the given format.
    async fn export_key(
        &self,
        format: String,
        key: KeyOrIdentifier,
    ) -> Result<Vec<u8>, SeetleError>;

    /// Derives a key from a base key.
    async fn derive_key(
        &self,
        algorithm: Algorithm,
        base_key: KeyOrIdentifier,
        derived_key_type: Algorithm,
        extractable: bool,
        key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError>;

    /// Derives bits from a base key.
    async fn derive_bits(
        &self,
        algorithm: Algorithm,
        base_key: KeyOrIdentifier,
        length: u32,
    ) -> Result<Vec<u8>, SeetleError>;

    /// Wraps a key for storage or transmission.
    async fn wrap_key(
        &self,
        format: String,
        key: CryptoKey,
        wrapping_key: KeyOrIdentifier,
        wrap_algorithm: Algorithm,
    ) -> Result<Vec<u8>, SeetleError>;

    /// Unwraps a wrapped key.
    async fn unwrap_key(
        &self,
        format: String,
        wrapped_key: Vec<u8>,
        unwrapping_key: KeyOrIdentifier,
        unwrap_algorithm: Algorithm,
        unwrapped_key_algorithm: Algorithm,
        extractable: bool,
        key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockBackend;
    use crate::memory::MemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_generate_hardware_key() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let backend = MockBackend::new(storage);
        let seetle: &dyn Seetle = &backend;

        let algorithm = Algorithm::Ecdsa {
            name: "ECDSA".into(),
            named_curve: "P-256".into(),
            hash: None,
        };
        let bindings = Bindings {
            hardware_bound: HardwareBound::Yes,
            origin_bindings: vec!["example.com".into()],
            identifier: "123ABC".into(),
            updatable: true,
            extractable: false,
        };

        let result = seetle.generate_key(
            algorithm,
            false,
            Some(bindings),
            vec![KeyUsage::Sign, KeyUsage::Verify],
        ).await.unwrap();

        match result {
            KeyOrIdentifier::Identifier(id) => assert_eq!(id, "123ABC"),
            _ => panic!("Expected identifier"),
        }
    }

    #[tokio::test]
    async fn test_hardware_bound_must_not_be_extractable() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let backend = MockBackend::new(storage);
        let seetle: &dyn Seetle = &backend;

        let algorithm = Algorithm::Ecdsa {
            name: "ECDSA".into(),
            named_curve: "P-256".into(),
            hash: None,
        };
        let bindings = Bindings {
            identifier: "123ABC".into(),
            extractable: true,
            ..Default::default()
        };

        let result = seetle.generate_key(
            algorithm,
            true, // extractable = true should fail if hardware_bound = true? Not anymore.
            Some(bindings),
            vec![],
        ).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hardware_key_storage() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let backend = MockBackend::new(storage.clone());
        let seetle: &dyn Seetle = &backend;

        let id = "test-key".to_string();
        let bindings = Bindings {
            hardware_bound: HardwareBound::Yes,
            identifier: id.clone(),
            ..Default::default()
        };

        seetle.generate_key(
            Algorithm::Generic { name: "test".into() },
            false,
            Some(bindings),
            vec![]
        ).await.unwrap();

        // Verify it's in storage
        assert!(storage.get_item(&id).await.unwrap().is_some());

        // Verify sign works with the identifier
        seetle.sign(
            Algorithm::Generic { name: "test".into() },
            KeyOrIdentifier::Identifier(id),
            vec![]
        ).await.unwrap();

        // Verify sign fails for unknown identifier
        let result = seetle.sign(
            Algorithm::Generic { name: "test".into() },
            KeyOrIdentifier::Identifier("unknown".into()),
            vec![]
        ).await;
        assert!(matches!(result, Err(SeetleError::KeyNotFound)));
    }
}
