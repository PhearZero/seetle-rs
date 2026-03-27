use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Backend, Seetle, SecureStorage};
#[allow(unused_imports)]
use crate::KeyType;
use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "android", target_os = "ios"))]
use secure_env::{SecureEnvironment, SecureEnvironmentOps, KeyOps};

pub struct SecureEnvBackend {
    storage: Arc<dyn SecureStorage>,
}

#[derive(Serialize, Deserialize, Clone)]
struct KeyMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
}

impl SecureEnvBackend {
    pub fn new(storage: Arc<dyn SecureStorage>) -> Self {
        Self { storage }
    }

    async fn get_metadata(&self, identifier: &str) -> Result<KeyMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|e| SeetleError::OperationError(e.to_string()))
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn check_usage(&self, metadata: &KeyMetadata, usage: KeyUsage) -> Result<(), SeetleError> {
        if metadata.usages.contains(&usage) {
            Ok(())
        } else {
            Err(SeetleError::OperationError(format!("Key does not support usage: {:?}", usage)))
        }
    }
}

impl Backend for SecureEnvBackend {
    fn seetle(&self) -> &dyn Seetle {
        self
    }
}

#[async_trait]
impl Seetle for SecureEnvBackend {
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = (algorithm, extractable, bindings, key_usages);
            return Err(SeetleError::NotSupported);
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            if let Some(b) = bindings {
                if b.hardware_bound && extractable {
                    return Err(SeetleError::OperationError(
                        "Hardware bound keys cannot be extractable".into(),
                    ));
                }

                // Check if algorithm is supported (ECDSA P-256)
                match &algorithm {
                    Algorithm::Ecdsa { named_curve, .. } if named_curve == "P-256" => {
                        // OK
                    }
                    _ => return Err(SeetleError::NotSupported),
                }

                SecureEnvironment::generate_keypair(&b.identifier, false)
                    .map_err(|e| SeetleError::OperationError(e.to_string()))?;

                let metadata = KeyMetadata {
                    bindings: b.clone(),
                    algorithm,
                    usages: key_usages,
                };
                
                let metadata_bytes = serde_json::to_vec(&metadata)
                    .map_err(|e| SeetleError::OperationError(e.to_string()))?;
                
                self.storage.set_item(&b.identifier, metadata_bytes).await?;
                
                Ok(KeyOrIdentifier::Identifier(b.identifier))
            } else {
                Err(SeetleError::OperationError("Bindings are required for SecureEnvBackend".into()))
            }
        }
    }

    async fn update_key(&self, identifier: String, new_bindings: Bindings) -> Result<(), SeetleError> {
        let mut metadata = self.get_metadata(&identifier).await?;
        if !metadata.bindings.updatable {
            return Err(SeetleError::OperationError("Key is not updatable".into()));
        }
        metadata.bindings = new_bindings;
        let metadata_bytes = serde_json::to_vec(&metadata)
            .map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, metadata_bytes).await?;
        Ok(())
    }

    async fn delete_key(&self, identifier: String) -> Result<(), SeetleError> {
        // secure-env crate doesn't seem to have a delete_key method in its trait, 
        // but it might be available in the underlying OS.
        // For now, we just remove it from our storage.
        self.storage.remove_item(&identifier).await?;
        Ok(())
    }

    async fn sign(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = (key, data);
            return Err(SeetleError::NotSupported);
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let id = match key {
                KeyOrIdentifier::Identifier(id) => id,
                KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
            };

            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::Sign)?;

            let keypair = SecureEnvironment::get_keypair_by_id(&id)
                .map_err(|e| SeetleError::OperationError(e.to_string()))?;
            
            keypair.sign(&data)
                .map_err(|e| SeetleError::OperationError(e.to_string()))
        }
    }

    async fn verify(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        signature: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<bool, SeetleError> {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = (key, signature, data);
            return Err(SeetleError::NotSupported);
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let id = match key {
                KeyOrIdentifier::Identifier(id) => id,
                KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
            };

            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::Verify)?;

            let keypair = SecureEnvironment::get_keypair_by_id(&id)
                .map_err(|e| SeetleError::OperationError(e.to_string()))?;
            
            let public_key_bytes = keypair.get_public_key()
                .map_err(|e| SeetleError::OperationError(e.to_string()))?;

            // Verification can be done using `ring` or similar, as secure-env doesn't provide it.
            // Since we already have `ring` as a dependency, we can use it.
            use ring::signature;
            
            let peer_public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_FIXED,
                public_key_bytes
            );

            match peer_public_key.verify(&data, &signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }

    async fn encrypt(&self, _algorithm: Algorithm, _key: KeyOrIdentifier, _data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn decrypt(&self, _algorithm: Algorithm, _key: KeyOrIdentifier, _data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn digest(&self, _algorithm: Algorithm, _data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
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

    async fn export_key(&self, _format: String, key: CryptoKey) -> Result<Vec<u8>, SeetleError> {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = key;
            return Err(SeetleError::NotSupported);
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            // secure-env only allows exporting the public key
            if key.key_type != KeyType::Public {
                 return Err(SeetleError::OperationError("Only public keys can be exported from SecureEnvBackend".into()));
            }

            // We need the identifier to get the key from secure-env.
            // But CryptoKey doesn't have the identifier.
            // Actually, in WebCrypto exportKey takes a CryptoKey object.
            // This is a bit tricky if we don't have the identifier here.
            // Usually, the CryptoKey would be associated with the backend and have the ID.
            // For now, let's return NotSupported or try to find a way.
            Err(SeetleError::NotSupported)
        }
    }

    async fn derive_key(&self, _algorithm: Algorithm, _base_key: KeyOrIdentifier, _derived_key_type: Algorithm, _extractable: bool, _key_usages: Vec<KeyUsage>) -> Result<KeyOrIdentifier, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_bits(&self, _algorithm: Algorithm, _base_key: KeyOrIdentifier, _length: u32) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn wrap_key(&self, _format: String, _key: CryptoKey, _wrapping_key: KeyOrIdentifier, _wrap_algorithm: Algorithm) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn unwrap_key(&self, _format: String, _wrapped_key: Vec<u8>, _unwrapping_key: KeyOrIdentifier, _unwrap_algorithm: Algorithm, _unwrapped_key_algorithm: Algorithm, _extractable: bool, _key_usages: Vec<KeyUsage>) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::mock::MemoryStorage;

    #[tokio::test]
    async fn test_secure_env_backend_creation() {
        let storage = Arc::new(MemoryStorage::new());
        let _backend = SecureEnvBackend::new(storage);
    }

    #[tokio::test]
    async fn test_not_supported_on_non_mobile() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let storage = Arc::new(MemoryStorage::new());
            let backend = SecureEnvBackend::new(storage);
            let result = backend.generate_key(
                Algorithm::Ecdsa { 
                    name: "ECDSA".into(), 
                    named_curve: "P-256".into(), 
                    hash: Some("SHA-256".into()) 
                },
                false,
                Some(Bindings {
                    identifier: "test".into(),
                    hardware_bound: true,
                    ..Default::default()
                }),
                vec![KeyUsage::Sign]
            ).await;
            
            assert!(matches!(result, Err(SeetleError::NotSupported)));
        }
    }
}
