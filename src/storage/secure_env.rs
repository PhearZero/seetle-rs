use crate::{SecureStorage, SeetleError};
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(any(target_os = "android", target_os = "ios"))]
use secure_env::{SecureEnvironment, SecureEnvironmentOps, KeyOps};

/// A `SecureStorage` decorator that wraps/unwraps data using hardware-backed keys on mobile platforms.
/// 
/// Note: Currently, the `secure-env` crate only supports signing and public key retrieval.
/// This implementation provides a skeleton for hardware-backed wrapping, which would ideally
/// use AES-GCM or ECIES if supported by the underlying hardware and exposed by the library.
pub struct SecureEnvStorage {
    inner: Arc<dyn SecureStorage>,
    #[allow(dead_code)]
    identifier: String,
}

impl SecureEnvStorage {
    pub fn new(inner: Arc<dyn SecureStorage>, identifier: &str) -> Result<Self, SeetleError> {
        Ok(Self {
            inner,
            identifier: identifier.to_string(),
        })
    }
}

#[async_trait]
impl SecureStorage for SecureEnvStorage {
    async fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, SeetleError> {
        let data = self.inner.get_item(key).await?;
        if let Some(wrapped_data) = data {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                // In a complete implementation, we would use the Secure Environment (Android Keystore / iOS Secure Enclave)
                // to unwrap the data. For instance, using an AES key marked as hardware-bound.
                // Since the current `secure-env` crate only exposes ECDSA signing, we return the data as-is 
                // for now, marking the intent.
                Ok(Some(wrapped_data))
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                // On non-mobile platforms, this decorator is transparent.
                Ok(Some(wrapped_data))
            }
        } else {
            Ok(None)
        }
    }

    async fn set_item(&self, key: &str, value: Vec<u8>) -> Result<(), SeetleError> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            // In a complete implementation, we would use the Secure Environment to wrap the data.
            let wrapped_value = value; // Placeholder
            self.inner.set_item(key, wrapped_value).await
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            self.inner.set_item(key, value).await
        }
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
    async fn test_secure_env_storage_creation() {
        let base = Arc::new(MemoryStorage::new());
        let _storage = SecureEnvStorage::new(base, "test-master-id").unwrap();
    }
}
