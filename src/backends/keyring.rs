use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Backend, Seetle, SecureStorage};
use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use keyring::Entry;
use ring::{rand, signature};
use ring::rand::SecureRandom;
use ring::signature::KeyPair;

/// A backend that uses the system keyring for secure storage of key material.
/// Cryptographic operations are performed using the `ring` crate.
pub struct KeyringBackend {
    storage: Arc<dyn SecureStorage>,
    service: String,
}

#[derive(Serialize, Deserialize)]
struct KeyMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
}

impl KeyringBackend {
    pub fn new(storage: Arc<dyn SecureStorage>) -> Self {
        Self {
            storage,
            service: "seelte".to_string(),
        }
    }

    pub fn with_service(storage: Arc<dyn SecureStorage>, service: &str) -> Self {
        Self {
            storage,
            service: service.to_string(),
        }
    }

    async fn get_metadata(&self, identifier: &str) -> Result<KeyMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|_e| SeetleError::DataError)
    }

    fn check_usage(&self, metadata: &KeyMetadata, usage: KeyUsage) -> Result<(), SeetleError> {
        if metadata.usages.contains(&usage) {
            Ok(())
        } else {
            Err(SeetleError::OperationError(format!("Key does not support usage: {:?}", usage)))
        }
    }

    fn get_key_entry(&self, identifier: &str) -> Result<Entry, SeetleError> {
        Entry::new(&self.service, identifier).map_err(|e| SeetleError::StorageError(e.to_string()))
    }
}

impl Backend for KeyringBackend {
    fn seetle(&self) -> &dyn Seetle {
        self
    }
}

#[async_trait]
impl Seetle for KeyringBackend {
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        if let Some(b) = bindings {
            if b.hardware_bound && extractable {
                return Err(SeetleError::OperationError(
                    "Hardware bound keys cannot be extractable".into(),
                ));
            }

            // Generate key material
            let key_material = match &algorithm {
                Algorithm::Ecdsa { named_curve, .. } => {
                    if named_curve != "P-256" {
                        return Err(SeetleError::NotSupported);
                    }
                    // For ECDSA, we generate a private key.
                    // ring::signature::EcdsaKeyPair::from_pkcs8 expects a PKCS8 encoded key.
                    // But we can generate it using ring::signature::EcdsaKeyPair::generate_pkcs8.
                    let rng = rand::SystemRandom::new();
                    let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
                        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &rng
                    ).map_err(|e| SeetleError::OperationError(format!("Key generation error: {}", e)))?;
                    pkcs8.as_ref().to_vec()
                }
                Algorithm::AesGcm { length, .. } => {
                    let rng = rand::SystemRandom::new();
                    let mut key = vec![0u8; (*length / 8) as usize];
                    rng.fill(&mut key).map_err(|_| SeetleError::OperationError("RNG error".into()))?;
                    key
                }
                _ => return Err(SeetleError::NotSupported),
            };

            // Store key material in keyring
            let entry = self.get_key_entry(&b.identifier)?;
            entry.set_password(&hex::encode(key_material)).map_err(|e| SeetleError::StorageError(e.to_string()))?;

            // Store metadata in storage
            let metadata = KeyMetadata {
                bindings: b.clone(),
                algorithm,
                usages: key_usages,
            };
            let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
            self.storage.set_item(&b.identifier, metadata_bytes).await?;

            Ok(KeyOrIdentifier::Identifier(b.identifier))
        } else {
            Err(SeetleError::NotSupported)
        }
    }

    async fn update_key(
        &self,
        identifier: String,
        new_bindings: Bindings,
    ) -> Result<(), SeetleError> {
        let mut metadata = self.get_metadata(&identifier).await?;
        if !metadata.bindings.updatable {
            return Err(SeetleError::OperationError("Key is not updatable".into()));
        }
        metadata.bindings = new_bindings;
        let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, metadata_bytes).await?;
        Ok(())
    }

    async fn delete_key(
        &self,
        identifier: String,
    ) -> Result<(), SeetleError> {
        let entry = self.get_key_entry(&identifier)?;
        entry.delete_credential().map_err(|e| SeetleError::StorageError(e.to_string()))?;
        self.storage.remove_item(&identifier).await?;
        Ok(())
    }

    async fn sign(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        match key {
            KeyOrIdentifier::Identifier(id) => {
                let metadata = self.get_metadata(&id).await?;
                self.check_usage(&metadata, KeyUsage::Sign)?;

                let entry = self.get_key_entry(&id)?;
                let key_hex = entry.get_password().map_err(|e| SeetleError::StorageError(e.to_string()))?;
                let key_material = hex::decode(key_hex).map_err(|_e| SeetleError::DataError)?;

                match &metadata.algorithm {
                    Algorithm::Ecdsa { named_curve, .. } => {
                        if named_curve != "P-256" {
                            return Err(SeetleError::NotSupported);
                        }
                        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                            &key_material,
                            &rand::SystemRandom::new()
                        ).map_err(|e| SeetleError::OperationError(format!("Key load error: {}", e)))?;

                        let rng = rand::SystemRandom::new();
                        let signature = key_pair.sign(&rng, &data).map_err(|e| SeetleError::OperationError(format!("Signing error: {}", e)))?;
                        Ok(signature.as_ref().to_vec())
                    }
                    _ => Err(SeetleError::NotSupported),
                }
            }
            _ => Err(SeetleError::NotSupported),
        }
    }

    async fn verify(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        signature: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<bool, SeetleError> {
        // Verification often uses public keys. For simplicity in this backend, 
        // we might just implement it if we have the private key or if we extract the public key.
        match key {
            KeyOrIdentifier::Identifier(id) => {
                let metadata = self.get_metadata(&id).await?;
                self.check_usage(&metadata, KeyUsage::Verify)?;

                let entry = self.get_key_entry(&id)?;
                let key_hex = entry.get_password().map_err(|e| SeetleError::StorageError(e.to_string()))?;
                let key_material = hex::decode(key_hex).map_err(|_e| SeetleError::DataError)?;

                match &metadata.algorithm {
                    Algorithm::Ecdsa { named_curve, .. } => {
                        if named_curve != "P-256" {
                            return Err(SeetleError::NotSupported);
                        }
                        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                            &key_material,
                            &rand::SystemRandom::new()
                        ).map_err(|e| SeetleError::OperationError(format!("Key load error: {}", e)))?;

                        let public_key = key_pair.public_key();
                        let peer_public_key = signature::UnparsedPublicKey::new(
                            &signature::ECDSA_P256_SHA256_FIXED,
                            public_key
                        );
                        
                        match peer_public_key.verify(&data, &signature) {
                            Ok(_) => Ok(true),
                            Err(_) => Ok(false),
                        }
                    }
                    _ => Err(SeetleError::NotSupported),
                }
            }
            _ => Err(SeetleError::NotSupported),
        }
    }

    async fn encrypt(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn decrypt(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn digest(
        &self,
        _algorithm: Algorithm,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn import_key(
        &self,
        _format: String,
        _key_data: Vec<u8>,
        _algorithm: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn export_key(
        &self,
        _format: String,
        _key: CryptoKey,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_key(
        &self,
        _algorithm: Algorithm,
        _base_key: KeyOrIdentifier,
        _derived_key_type: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_bits(
        &self,
        _algorithm: Algorithm,
        _base_key: KeyOrIdentifier,
        _length: u32,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn wrap_key(
        &self,
        _format: String,
        _key: CryptoKey,
        _wrapping_key: KeyOrIdentifier,
        _wrap_algorithm: Algorithm,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn unwrap_key(
        &self,
        _format: String,
        _wrapped_key: Vec<u8>,
        _unwrapping_key: KeyOrIdentifier,
        _unwrap_algorithm: Algorithm,
        _unwrapped_key_algorithm: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }
}

#[cfg(test)]
mod keyring_tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn test_keyring_backend_ecdsa() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let backend = KeyringBackend::new(storage);
        let seetle = backend.seetle();

        let algorithm = Algorithm::Ecdsa {
            name: "ECDSA".into(),
            named_curve: "P-256".into(),
            hash: Some("SHA-256".into()),
        };
        let bindings = Bindings {
            identifier: "test-key-keyring".into(),
            hardware_bound: true,
            ..Default::default()
        };

        // This might fail if no keyring service is available in the environment
        let result = seetle.generate_key(
            algorithm.clone(),
            false,
            Some(bindings),
            vec![KeyUsage::Sign, KeyUsage::Verify],
        ).await;

        match result {
            Ok(KeyOrIdentifier::Identifier(id)) => {
                assert_eq!(id, "test-key-keyring");
                
                let data = b"hello world".to_vec();
                let sign_result = seetle.sign(algorithm.clone(), KeyOrIdentifier::Identifier(id.clone()), data.clone()).await;
                
                match sign_result {
                    Ok(signature) => {
                        assert!(!signature.is_empty());
                        let verified = seetle.verify(algorithm, KeyOrIdentifier::Identifier(id), signature, data).await.unwrap();
                        assert!(verified);
                    }
                    Err(SeetleError::StorageError(e)) => {
                        println!("Keyring sign failed (expected in some envs): {}", e);
                    }
                    Err(e) => panic!("Unexpected sign error: {:?}", e),
                }
            }
            Err(e) => {
                println!("Keyring test skipped or failed due to environment: {:?}", e);
                // If it's a StorageError, it's likely the missing keyring service
                if !matches!(e, SeetleError::StorageError(_)) {
                    panic!("Unexpected error: {:?}", e);
                }
            }
            _ => panic!("Expected identifier"),
        }
    }
}
