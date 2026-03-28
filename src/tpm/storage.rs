use crate::{SecureStorage, SeetleError};
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(feature = "tpm")]
use std::sync::Mutex;
#[cfg(feature = "tpm")]
use tss_esapi::{
    interface_types::{
        algorithm::{PublicAlgorithm, HashingAlgorithm},
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        PublicBuilder,
        MaxBuffer,
        Digest,
        PublicKeyedHashParameters,
        KeyedHashScheme,
    },
    attributes::ObjectAttributesBuilder,
    Context,
};
#[cfg(feature = "tpm")]
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};

/// A `SecureStorage` decorator that wraps/unwraps data using TPM 2.0.
/// 
/// This allows other backends (like `XHDBackend`) to have their metadata
/// hardware-protected by the TPM.
pub struct TpmStorage {
    inner: Arc<dyn SecureStorage>,
    #[cfg(feature = "tpm")]
    context: Arc<Mutex<Context>>,
}

impl TpmStorage {
    #[cfg(feature = "tpm")]
    pub fn new(inner: Arc<dyn SecureStorage>, context: Arc<Mutex<Context>>) -> Result<Self, SeetleError> {
        Ok(Self {
            inner,
            context,
        })
    }

    #[cfg(not(feature = "tpm"))]
    pub fn new(inner: Arc<dyn SecureStorage>) -> Result<Self, SeetleError> {
        Ok(Self {
            inner,
        })
    }

    #[cfg(feature = "tpm")]
    fn get_encryption_key(&self, context: &mut Context) -> Result<LessSafeKey, SeetleError> {
        context.set_sessions((Some(AuthSession::Password), None, None));

        let key_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|e| SeetleError::OperationError(format!("TPM error: {}", e)))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(key_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::HMAC_SHA_256))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(|e| SeetleError::OperationError(format!("TPM error: {}", e)))?;

        let primary_key_handle = context
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .map_err(|e| SeetleError::OperationError(format!("TPM create_primary error: {}", e)))?
            .key_handle;

        let salt = MaxBuffer::try_from(b"seetle-storage-encryption-key-v1".to_vec())
            .map_err(|_| SeetleError::OperationError("Failed to create salt buffer".into()))?;

        let hmac_result = context
            .hmac(primary_key_handle.into(), salt, HashingAlgorithm::Sha256)
            .map_err(|e| SeetleError::OperationError(format!("TPM hmac error: {}", e)))?;

        let _ = context.flush_context(primary_key_handle.into());
        context.set_sessions((None, None, None));

        let key_bytes: Vec<u8> = hmac_result.to_vec();
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| SeetleError::OperationError("Failed to create ring key".into()))?;

        Ok(LessSafeKey::new(unbound_key))
    }
}

#[async_trait]
impl SecureStorage for TpmStorage {
    async fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, SeetleError> {
        let data = self.inner.get_item(key).await?;
        if let Some(wrapped_data) = data {
            #[cfg(feature = "tpm")]
            {
                if wrapped_data.len() < NONCE_LEN + 16 { // Nonce + at least 16 bytes for tag/data
                    return Err(SeetleError::OperationError("Invalid wrapped data (too short)".into()));
                }

                let mut context = self.context.lock().map_err(|_| SeetleError::OperationError("Failed to lock TPM context".into()))?;
                let key = self.get_encryption_key(&mut context)?;

                let (nonce_bytes, ciphertext) = wrapped_data.split_at(NONCE_LEN);
                let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
                    .map_err(|_| SeetleError::OperationError("Failed to create nonce".into()))?;

                let mut in_out = ciphertext.to_vec();
                let decrypted_data = key.open_in_place(nonce, Aad::empty(), &mut in_out)
                    .map_err(|e| SeetleError::OperationError(format!("Software decryption error: {}", e)))?;

                Ok(Some(decrypted_data.to_vec()))
            }
            #[cfg(not(feature = "tpm"))]
            {
                Ok(Some(wrapped_data))
            }
        } else {
            Ok(None)
        }
    }

    async fn set_item(&self, key: &str, value: Vec<u8>) -> Result<(), SeetleError> {
        let wrapped_value = {
            #[cfg(feature = "tpm")]
            {
                let mut context = self.context.lock().map_err(|_| SeetleError::OperationError("Failed to lock TPM context".into()))?;
                let key = self.get_encryption_key(&mut context)?;

                context.set_sessions((None, None, None));
                let nonce_vec = context.get_random(NONCE_LEN)
                    .map_err(|e| SeetleError::OperationError(format!("TPM error: {}", e)))?
                    .to_vec();
                let nonce = Nonce::try_assume_unique_for_key(&nonce_vec)
                    .map_err(|_| SeetleError::OperationError("Failed to create nonce".into()))?;

                let mut in_out = value.clone();
                key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                    .map_err(|_| SeetleError::OperationError("Software encryption error".into()))?;

                let mut result = nonce_vec;
                result.extend_from_slice(&in_out);
                result
            }
            #[cfg(not(feature = "tpm"))]
            {
                value
            }
        };

        self.inner.set_item(key, wrapped_value).await
    }

    async fn remove_item(&self, key: &str) -> Result<(), SeetleError> {
        self.inner.remove_item(key).await
    }

    async fn list_items(&self) -> Result<Vec<String>, SeetleError> {
        self.inner.list_items().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;
    #[cfg(feature = "tpm")]
    use crate::tpm::TpmBackend;

    #[tokio::test]
    async fn test_tpm_get_random_basic() {
        #[cfg(feature = "tpm")]
        {
            let context_res = TpmBackend::create_context(None);
            if let Ok(ctx) = context_res {
                let mut context = ctx.lock().map_err(|_| SeetleError::OperationError("Lock failed".into())).unwrap();
                let random = context.get_random(16);
                assert!(random.is_ok(), "TPM get_random should succeed if TPM is present: {:?}", random.err());
                assert_eq!(random.unwrap().len(), 16);
            } else {
                println!("Skipping get_random test: No TPM available");
            }
        }
    }

    #[tokio::test]
    async fn test_tpm_storage_initialization() {
        let base = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        {
            let result = TpmStorage::new(base);
            assert!(result.is_ok());
        }

        #[cfg(feature = "tpm")]
        {
            let context = TpmBackend::create_context(None);
            if let Ok(ctx) = context {
                let result = TpmStorage::new(base, ctx);
                assert!(result.is_ok());
            } else {
                println!("Skipping TPM storage initialization test: No TPM available");
            }
        }
    }

    #[tokio::test]
    async fn test_tpm_storage_roundtrip() {
        let base = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        let storage = TpmStorage::new(base).unwrap();

        #[cfg(feature = "tpm")]
        let storage = {
            let context = TpmBackend::create_context(None);
            match context {
                Ok(ctx) => TpmStorage::new(base, ctx).unwrap(),
                Err(_) => {
                    println!("Skipping roundtrip test: No TPM available");
                    return;
                }
            }
        };

        let key = "test-key-123";
        let value = b"sensitive-metadata-to-be-wrapped".to_vec();

        // Store item
        if let Err(e) = storage.set_item(key, value.clone()).await {
            panic!("Failed to set item: {:?}", e);
        }

        // Retrieve item
        let retrieved = storage.get_item(key).await
            .expect("Failed to get item")
            .expect("Item not found");

        assert_eq!(value, retrieved, "Retrieved value should match original");

        // Remove item
        storage.remove_item(key).await.expect("Failed to remove item");
        let after_remove = storage.get_item(key).await.expect("Failed to get item after remove");
        assert!(after_remove.is_none(), "Item should be gone after removal");
    }

    #[tokio::test]
    async fn test_tpm_storage_wrapping_verification() {
        let base = Arc::new(MemoryStorage::new());
        let base_clone = base.clone();
        
        #[cfg(not(feature = "tpm"))]
        let storage = TpmStorage::new(base).unwrap();

        #[cfg(feature = "tpm")]
        let storage = {
            let context = TpmBackend::create_context(None);
            match context {
                Ok(ctx) => TpmStorage::new(base, ctx).unwrap(),
                Err(_) => return, // Skip
            }
        };

        let key = "wrap-test";
        let value = b"plain-text-data".to_vec();

        if let Err(e) = storage.set_item(key, value.clone()).await {
            panic!("Failed to set item: {:?}", e);
        }

        // Check the underlying storage directly
        let raw_data = base_clone.get_item(key).await.unwrap().unwrap();

        #[cfg(feature = "tpm")]
        {
            // If TPM is used, raw_data should be different from value
            // (it should be Nonce + ciphertext + tag)
            assert_ne!(raw_data, value, "Data in base storage should be encrypted/wrapped");
            assert!(raw_data.len() >= NONCE_LEN + value.len() + 16, "Wrapped data should include Nonce and GCM tag");
        }

        #[cfg(not(feature = "tpm"))]
        {
            // If TPM is NOT used, it should be the same (pass-through)
            assert_eq!(raw_data, value, "Data in base storage should match original when TPM is disabled");
        }
    }
}
