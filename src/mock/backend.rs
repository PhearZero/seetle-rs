use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Seetle, SecureStorage, KeyType, KeyMetadata};
use async_trait::async_trait;
use std::sync::Arc;

/// A mock backend for testing.
pub struct MockBackend {
    storage: Arc<dyn SecureStorage>,
}

impl MockBackend {
    pub fn new(storage: Arc<dyn SecureStorage>) -> Self {
        Self { storage }
    }
}


#[async_trait]
impl Seetle for MockBackend {
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        if let Some(mut b) = bindings {
            b.extractable = extractable;
            // Store metadata in secure storage
            let metadata = serde_json::to_vec(&b)
                .map_err(|e| SeetleError::OperationError(e.to_string()))?;
            self.storage.set_item(&b.identifier, metadata).await?;

            Ok(KeyOrIdentifier::Identifier(b.identifier))
        } else {
            Ok(KeyOrIdentifier::Key(CryptoKey {
                key_type: KeyType::Secret,
                extractable,
                algorithm,
                usages: vec![],
            }))
        }
    }

    async fn update_key(
        &self,
        identifier: String,
        new_bindings: Bindings,
    ) -> Result<(), SeetleError> {
        if self.storage.get_item(&identifier).await?.is_none() {
            return Err(SeetleError::KeyNotFound);
        }
        let metadata = serde_json::to_vec(&new_bindings)
            .map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, metadata).await?;
        Ok(())
    }

    async fn delete_key(
        &self,
        identifier: String,
    ) -> Result<(), SeetleError> {
        self.storage.remove_item(&identifier).await?;
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<String>, SeetleError> {
        let keys = self.storage.list_items().await?;
        Ok(keys.into_iter().filter(|k| !k.starts_with('.')).collect())
    }

    async fn get_key_metadata(&self, identifier: String) -> Result<KeyMetadata, SeetleError> {
        let data = self.storage.get_item(&identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        let bindings: Bindings = serde_json::from_slice(&data).unwrap_or_default();

        Ok(KeyMetadata {
            identifier,
            algorithm: "Mock".to_string(),
            hardware_bound: bindings.hardware_bound,
            extractable: bindings.extractable,
            source_key_identifier: None,
            ..Default::default()
        })
    }

    async fn sign(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        if let KeyOrIdentifier::Identifier(id) = key {
            if self.storage.get_item(&id).await?.is_none() {
                return Err(SeetleError::KeyNotFound);
            }
        }
        Ok(vec![0; 64]) // Return a fake signature
    }

    async fn verify(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _signature: Vec<u8>,
        _data: Vec<u8>,
    ) -> Result<bool, SeetleError> {
        Ok(true)
    }

    async fn encrypt(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Ok(vec![0; 32])
    }

    async fn decrypt(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Ok(vec![0; 32])
    }

    async fn digest(
        &self,
        _algorithm: Algorithm,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Ok(vec![0; 32])
    }

    async fn import_key(
        &self,
        _format: String,
        _key_data: Vec<u8>,
        _algorithm: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError> {
        Ok(CryptoKey {
            key_type: KeyType::Secret,
            extractable: true,
            algorithm: Algorithm::Generic { name: "mock".to_string() },
            usages: vec![],
        })
    }

    async fn export_key(
        &self,
        _format: String,
        key: KeyOrIdentifier,
    ) -> Result<Vec<u8>, SeetleError> {
        match key {
            KeyOrIdentifier::Identifier(id) => {
                let data = self.storage.get_item(&id).await?
                    .ok_or(SeetleError::KeyNotFound)?;
                let bindings: Bindings = serde_json::from_slice(&data).unwrap_or_default();
                if !bindings.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                Ok(vec![0x42; 64]) // Return dummy key material
            }
            KeyOrIdentifier::Key(k) => {
                if !k.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                Ok(vec![0x42; 64])
            }
        }
    }

    async fn derive_key(
        &self,
        _algorithm: Algorithm,
        _base_key: KeyOrIdentifier,
        _derived_key_type: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        Ok(KeyOrIdentifier::Identifier("derived-mock-key".to_string()))
    }

    async fn derive_bits(
        &self,
        _algorithm: Algorithm,
        _base_key: KeyOrIdentifier,
        length: u32,
    ) -> Result<Vec<u8>, SeetleError> {
        Ok(vec![0x42; (length / 8) as usize])
    }

    async fn wrap_key(
        &self,
        _format: String,
        _key: CryptoKey,
        _wrapping_key: KeyOrIdentifier,
        _wrap_algorithm: Algorithm,
    ) -> Result<Vec<u8>, SeetleError> {
        Ok(vec![0; 32])
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
        Ok(CryptoKey {
            key_type: KeyType::Secret,
            extractable: true,
            algorithm: Algorithm::Generic { name: "mock".to_string() },
            usages: vec![],
        })
    }
}
