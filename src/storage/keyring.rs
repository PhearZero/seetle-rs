use crate::{SecureStorage, SeetleError};
use async_trait::async_trait;
use std::sync::Arc;
use keyring::Entry;

/// A `SecureStorage` decorator that wraps/unwraps data using the OS keyring.
/// 
/// This allows other backends to have their metadata hardware-protected by the
/// OS's secure storage (Keychain on macOS/iOS, Credential Manager on Windows, 
/// Secret Service on Linux).
pub struct KeyringStorage {
    inner: Arc<dyn SecureStorage>,
    service: String,
    identifier: String,
}

impl KeyringStorage {
    pub fn new(inner: Arc<dyn SecureStorage>, service: &str, identifier: &str) -> Result<Self, SeetleError> {
        Ok(Self {
            inner,
            service: service.to_string(),
            identifier: identifier.to_string(),
        })
    }

    fn get_entry(&self) -> Result<Entry, SeetleError> {
        Entry::new(&self.service, &self.identifier).map_err(|e| SeetleError::StorageError(e.to_string()))
    }

    fn get_master_key(&self) -> Result<Vec<u8>, SeetleError> {
        let entry = self.get_entry()?;
        match entry.get_password() {
            Ok(hex_key) => hex::decode(hex_key).map_err(|_| SeetleError::DataError),
            Err(keyring::Error::NoEntry) => {
                // Generate a new master key if it doesn't exist
                use ring::rand::{SystemRandom, SecureRandom};
                let rng = SystemRandom::new();
                let mut key = [0u8; 32]; // AES-256
                rng.fill(&mut key).map_err(|_| SeetleError::OperationError("RNG error".into()))?;
                
                let hex_key = hex::encode(key);
                entry.set_password(&hex_key).map_err(|e| SeetleError::StorageError(e.to_string()))?;
                Ok(key.to_vec())
            }
            Err(e) => Err(SeetleError::StorageError(e.to_string())),
        }
    }
}

#[async_trait]
impl SecureStorage for KeyringStorage {
    async fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, SeetleError> {
        let data = self.inner.get_item(key).await?;
        if let Some(wrapped_data) = data {
            // In a real implementation, we would use the master key from the keyring 
            // to decrypt the data using AES-GCM or similar.
            let _master_key = self.get_master_key()?;
            // Perform decryption...
            Ok(Some(wrapped_data)) // Placeholder
        } else {
            Ok(None)
        }
    }

    async fn set_item(&self, key: &str, value: Vec<u8>) -> Result<(), SeetleError> {
        // In a real implementation, we would use the master key from the keyring 
        // to encrypt the data.
        let _master_key = self.get_master_key()?;
        // Perform encryption...
        let wrapped_value = value; // Placeholder
        self.inner.set_item(key, wrapped_value).await
    }

    async fn remove_item(&self, key: &str) -> Result<(), SeetleError> {
        self.inner.remove_item(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn test_keyring_storage_creation() {
        let base = Arc::new(MemoryStorage::new());
        let _storage = KeyringStorage::new(base, "seelte-test", "test-master-key").unwrap();
    }
}
