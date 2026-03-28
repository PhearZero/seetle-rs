use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Seetle, SecureStorage, KeyMetadata};
use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

#[cfg(feature = "tpm")]
use std::sync::Mutex;
#[cfg(feature = "tpm")]
use tss_esapi::Context;

/// A backend that uses a TPM 2.0 (via tss-esapi) for hardware-backed keys.
pub struct TpmBackend {
    storage: Arc<dyn SecureStorage>,
    #[cfg(feature = "tpm")]
    context: Arc<Mutex<Context>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct TpmMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
    /// The wrapped private key blob from TPM.
    key_blob: Vec<u8>,
    /// The public part of the key.
    public_blob: Vec<u8>,
}

impl TpmBackend {
    #[cfg(feature = "tpm")]
    pub fn create_context(tcti_name_conf: Option<&str>) -> Result<Arc<Mutex<Context>>, SeetleError> {
        use std::str::FromStr;
        use tss_esapi::TctiNameConf;

        // 1. If explicit TCTI provided, use only that.
        if let Some(conf) = tcti_name_conf {
            let tcti = TctiNameConf::from_str(conf).map_err(|e| SeetleError::OperationError(format!("Invalid TCTI string '{}': {}", conf, e)))?;
            let context = Context::new(tcti).map_err(|e| SeetleError::OperationError(format!("Failed to initialize TPM context with TCTI '{}': {}", conf, e)))?;
            return Ok(Arc::new(Mutex::new(context)));
        }

        // 2. Try environment variable
        if let Ok(tcti) = TctiNameConf::from_environment_variable() {
            if let Ok(context) = Context::new(tcti) {
                return Ok(Arc::new(Mutex::new(context)));
            }
        }

        // 3. Try direct device access through the Kernel Resource Manager node (/dev/tpmrm0)
        if let Ok(tcti) = TctiNameConf::from_str("device:/dev/tpmrm0") {
            if let Ok(context) = Context::new(tcti) {
                return Ok(Arc::new(Mutex::new(context)));
            }
        }

        // 4. Try tabrmd (Access Broker & Resource Manager daemon)
        if let Ok(tcti) = TctiNameConf::from_str("tabrmd:") {
            if let Ok(context) = Context::new(tcti) {
                return Ok(Arc::new(Mutex::new(context)));
            }
        }

        Err(SeetleError::OperationError(
            "Failed to initialize TPM context. Tried environment variable, tabrmd, and direct device access (/dev/tpmrm0). \
             Please ensure: \
             1. 'tpm2-abrmd' is installed and running, OR \
             2. You have read/write access to /dev/tpmrm0 (e.g., 'sudo usermod -aG tss $USER' and log out/in), OR \
             3. You pass a specific device via --tpm-device."
             .to_string()
        ))
    }

    #[cfg(feature = "tpm")]
    pub fn new(storage: Arc<dyn SecureStorage>, context: Arc<Mutex<Context>>) -> Result<Self, SeetleError> {
        Ok(Self {
            storage,
            context,
        })
    }

    #[cfg(not(feature = "tpm"))]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, SeetleError> {
        Ok(Self {
            storage,
        })
    }

    async fn get_metadata(&self, identifier: &str) -> Result<TpmMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|e| SeetleError::OperationError(e.to_string()))
    }
}


#[async_trait]
impl Seetle for TpmBackend {
    async fn generate_key(
        &self,
        _algorithm: Algorithm,
        _extractable: bool,
        _bindings: Option<Bindings>,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        #[cfg(not(feature = "tpm"))]
        {
            return Err(SeetleError::NotSupported);
        }

        #[cfg(feature = "tpm")]
        {
            let algorithm = _algorithm;
            let extractable = _extractable;
            let bindings = _bindings;
            if let Some(mut b) = bindings {
                b.extractable = extractable;
                // In a real TPM implementation, we would:
                // 1. Create/Retrieve a Primary Key in the Storage Hierarchy.
                // 2. Use `create_key` to generate a child key (ECC or RSA).
                // 3. Store the resulting `private` (wrapped) and `public` blobs in our metadata.
                
                // For now, this is a skeleton implementation showing the intent.
                // tss-esapi requires a lot of boilerplate for full key creation.
                
                match algorithm {
                    Algorithm::Generic { .. } | Algorithm::Raw { .. } => {
                        let requested_len = if let Algorithm::Raw { length } = algorithm {
                            (length / 8) as usize
                        } else {
                            32 // Default to 256 bits for generic seeds
                        };

                        let bits = {
                            let mut context = self.context.lock().unwrap();
                            let mut accumulated = Vec::new();
                            while accumulated.len() < requested_len {
                                let to_get = requested_len - accumulated.len();
                                let next_batch = context.get_random(std::cmp::min(to_get, 64))
                                    .map_err(|e| SeetleError::OperationError(format!("TPM get_random error: {}", e)))?;
                                accumulated.extend_from_slice(&next_batch);
                            }
                            accumulated
                        };

                        let metadata = TpmMetadata {
                            bindings: b.clone(),
                            algorithm: algorithm.clone(),
                            usages: _key_usages,
                            public_blob: Vec::new(),
                            key_blob: bits,
                        };
                        let data = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
                        self.storage.set_item(&b.identifier, data).await?;
                        return Ok(KeyOrIdentifier::Identifier(b.identifier));
                    }
                    Algorithm::Ecdsa { ref named_curve, .. } if named_curve == "P-256" => {
                        // ECDSA P-256 logic here
                    }
                    Algorithm::Ed25519 { .. } => {
                        // Ed25519 logic here
                    }
                    Algorithm::RsaPss { modulus_length, .. } if modulus_length >= 2048 => {
                        // RSA-PSS logic here
                    }
                    _ => return Err(SeetleError::NotSupported),
                }

                return Err(SeetleError::OperationError("TPM key generation for this algorithm not fully implemented in this skeleton".into()));
            }

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
            return Err(SeetleError::AccessDenied);
        }
        metadata.bindings = new_bindings;
        let data = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, data).await?;
        Ok(())
    }

    async fn delete_key(
        &self,
        identifier: String,
    ) -> Result<(), SeetleError> {
        self.storage.remove_item(&identifier).await
    }

    async fn list_keys(&self) -> Result<Vec<String>, SeetleError> {
        let keys = self.storage.list_items().await?;
        Ok(keys.into_iter().filter(|k| !k.starts_with('.')).collect())
    }

    async fn get_key_metadata(&self, identifier: String) -> Result<KeyMetadata, SeetleError> {
        let metadata = self.get_metadata(&identifier).await?;
        
        Ok(KeyMetadata {
            identifier,
            algorithm: format!("{:?}", metadata.algorithm),
            usages: metadata.usages,
            hardware_bound: metadata.bindings.hardware_bound,
            extractable: metadata.bindings.extractable,
            public_key: Some(metadata.public_blob),
            source_key_identifier: None,
            ..Default::default()
        })
    }

    async fn sign(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        #[cfg(not(feature = "tpm"))]
        {
            return Err(SeetleError::NotSupported);
        }

        #[cfg(feature = "tpm")]
        {
            let key = _key;
            let identifier = match key {
                KeyOrIdentifier::Identifier(id) => id,
                KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
            };

            let _metadata = self.get_metadata(&identifier).await?;
            
            // 1. Load the key into TPM using the blobs from metadata.
            // 2. Execute `sign` operation.
            // 3. Flush the key from TPM to save resources.

            Err(SeetleError::OperationError("TPM signing not fully implemented in this skeleton".into()))
        }
    }

    async fn verify(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        _signature: Vec<u8>,
        _data: Vec<u8>,
    ) -> Result<bool, SeetleError> {
        // Verification can often be done on the host if the public key is known.
        // For TPM keys, we can also use TPM to verify, but it's usually faster on host.
        // Using `ring` for host-side verification is a common pattern in this library.
        
        let _public_key = match key {
            KeyOrIdentifier::Identifier(id) => {
                let _metadata = self.get_metadata(&id).await?;
                // In TPM, public_blob is a TPM2B_PUBLIC structure.
                // We'd need to extract the raw public key bytes.
                return Err(SeetleError::OperationError("TPM verification not implemented".into()));
            }
            KeyOrIdentifier::Key(_k) => return Err(SeetleError::NotSupported),
        };
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
        #[cfg(not(feature = "tpm"))]
        {
            return Err(SeetleError::NotSupported);
        }

        #[cfg(feature = "tpm")]
        {
            let length = _length;
            let base_key = _base_key;
            let identifier = match base_key {
                KeyOrIdentifier::Identifier(id) => id,
                KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
            };

            // 1. Try to load from storage for persistence
            let key_material = if let Ok(Some(data)) = self.storage.get_item(&identifier).await {
                // Check if it's metadata (JSON)
                if let Ok(metadata) = serde_json::from_slice::<TpmMetadata>(&data) {
                    metadata.key_blob
                } else {
                    // Fallback to raw bits (backward compatibility)
                    data
                }
            } else {
                return Err(SeetleError::KeyNotFound);
            };

            if key_material.len() == (length / 8) as usize {
                Ok(key_material)
            } else if length == 512 {
                // Consistent with KeyringBackend: if asking for 512 bits, use SHA-512 to derive from key material.
                use ring::digest;
                let hash = digest::digest(&digest::SHA512, &key_material);
                Ok(hash.as_ref().to_vec())
            } else {
                Err(SeetleError::OperationError(format!(
                    "Stored seed for {} has wrong length and cannot be derived: expected {}, got {}", 
                    identifier, (length / 8), key_material.len()
                )))
            }
        }
    }

    async fn export_key(
        &self,
        _format: String,
        key: KeyOrIdentifier,
    ) -> Result<Vec<u8>, SeetleError> {
        match key {
            KeyOrIdentifier::Identifier(id) => {
                let metadata = self.get_metadata(&id).await?;
                if !metadata.bindings.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                // For bits/generic, the key material is in key_blob
                if metadata.key_blob.is_empty() {
                    return Err(SeetleError::OperationError("Key material not available for export in this skeleton".into()));
                }
                Ok(metadata.key_blob.clone())
            }
            KeyOrIdentifier::Key(k) => {
                if !k.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                Err(SeetleError::NotSupported)
            }
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;

    #[tokio::test]
    async fn test_tpm_backend_creation() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        {
            let result = TpmBackend::new(storage);
            assert!(result.is_ok());
        }

        #[cfg(feature = "tpm")]
        {
            let context = TpmBackend::create_context(None);
            if let Ok(ctx) = context {
                let result = TpmBackend::new(storage, ctx);
                assert!(result.is_ok());
            } else {
                println!("Skipping TPM backend creation test: No TPM available");
            }
        }
    }

    #[tokio::test]
    async fn test_tpm_derive_bits() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        let backend = TpmBackend::new(storage.clone()).unwrap();

        #[cfg(feature = "tpm")]
        let backend = {
            let context = TpmBackend::create_context(None);
            match context {
                Ok(ctx) => TpmBackend::new(storage.clone(), ctx).unwrap(),
                Err(_) => return, // Skip
            }
        };

        let identifier = "test-seed-128";
        let length = 128; // 16 bytes

        #[cfg(feature = "tpm")]
        {
            // First generation
            backend.generate_key(
                Algorithm::Raw { length },
                false,
                Some(Bindings {
                    identifier: identifier.into(),
                    ..Default::default()
                }),
                vec![]
            ).await.expect("Failed to generate seed via TPM");
        }

        let bits_result = backend.derive_bits(
            Algorithm::Raw { length },
            KeyOrIdentifier::Identifier(identifier.into()),
            length
        ).await;

        #[cfg(not(feature = "tpm"))]
        {
            assert!(matches!(bits_result, Err(SeetleError::NotSupported)));
        }

        #[cfg(feature = "tpm")]
        {
            let bits = bits_result.expect("Failed to derive bits via TPM");
            assert_eq!(bits.len(), 16);

            // Verify persistence in storage (it should be stored as metadata now)
            let stored_data = storage.get_item(identifier).await.unwrap()
                .expect("Metadata should be persisted in storage");
            let metadata: TpmMetadata = serde_json::from_slice(&stored_data).unwrap();
            assert_eq!(bits, metadata.key_blob);

            // Second call should return same bits from storage
            let bits2 = backend.derive_bits(
                Algorithm::Raw { length },
                KeyOrIdentifier::Identifier(identifier.into()),
                length
            ).await.unwrap();

            assert_eq!(bits, bits2);
        }
    }

    #[tokio::test]
    async fn test_tpm_delete_key() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        let backend = TpmBackend::new(storage.clone()).unwrap();

        #[cfg(feature = "tpm")]
        let backend = {
            let context = TpmBackend::create_context(None);
            match context {
                Ok(ctx) => TpmBackend::new(storage.clone(), ctx).unwrap(),
                Err(_) => return, // Skip
            }
        };

        let identifier = "key-to-delete";
        storage.set_item(identifier, vec![1, 2, 3]).await.unwrap();
        
        backend.delete_key(identifier.to_string()).await.expect("Delete should succeed");
        
        let exists = storage.get_item(identifier).await.unwrap().is_some();
        assert!(!exists, "Key should be removed from storage");
    }
}
