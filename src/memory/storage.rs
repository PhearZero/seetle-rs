use crate::{SecureStorage, SeetleError};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;

/// An in-memory implementation of `SecureStorage`.
pub struct MemoryStorage {
    items: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            items: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecureStorage for MemoryStorage {
    async fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, SeetleError> {
        Ok(self.items.lock().await.get(key).cloned())
    }

    async fn set_item(&self, key: &str, value: Vec<u8>) -> Result<(), SeetleError> {
        self.items.lock().await.insert(key.to_string(), value);
        Ok(())
    }

    async fn remove_item(&self, key: &str) -> Result<(), SeetleError> {
        self.items.lock().await.remove(key);
        Ok(())
    }

    async fn list_items(&self) -> Result<Vec<String>, SeetleError> {
        Ok(self.items.lock().await.keys().cloned().collect())
    }
}
