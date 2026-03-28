use crate::{SecureStorage, SeetleError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// A simple file-based persistent storage for metadata.
pub struct FileStorage {
    path: PathBuf,
    extension: Option<String>,
    cache: RwLock<HashMap<String, Vec<u8>>>,
}

impl FileStorage {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, SeetleError> {
        Self::new_with_extension(path, None)
    }

    pub fn new_with_extension(path: impl AsRef<Path>, extension: Option<String>) -> Result<Self, SeetleError> {
        let path = path.as_ref().to_path_buf();
        let mut cache = HashMap::new();
        
        if path.exists() {
            for entry in fs::read_dir(&path).map_err(|e| SeetleError::StorageError(e.to_string()))? {
                let entry = entry.map_err(|e| SeetleError::StorageError(e.to_string()))?;
                if entry.file_type().map_err(|e| SeetleError::StorageError(e.to_string()))?.is_file() {
                    let file_name = entry.file_name().into_string().map_err(|_| SeetleError::DataError)?;
                    
                    let key = if let Some(ext) = &extension {
                        if file_name.ends_with(ext) {
                            file_name[..file_name.len() - ext.len()].to_string()
                        } else {
                            continue; // Skip files without the correct extension
                        }
                    } else {
                        file_name
                    };

                    let data = fs::read(entry.path()).map_err(|e| SeetleError::StorageError(e.to_string()))?;
                    cache.insert(key, data);
                }
            }
        }
        
        Ok(Self {
            path,
            extension,
            cache: RwLock::new(cache),
        })
    }
}

#[async_trait]
impl SecureStorage for FileStorage {
    async fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, SeetleError> {
        let cache = self.cache.read().map_err(|e| SeetleError::OperationError(e.to_string()))?;
        Ok(cache.get(key).cloned())
    }

    async fn set_item(&self, key: &str, value: Vec<u8>) -> Result<(), SeetleError> {
        let mut cache = self.cache.write().map_err(|e| SeetleError::OperationError(e.to_string()))?;
        if !self.path.exists() {
            fs::create_dir_all(&self.path).map_err(|e| SeetleError::StorageError(e.to_string()))?;
        }
        let file_name = if let Some(ext) = &self.extension {
            format!("{}{}", key, ext)
        } else {
            key.to_string()
        };
        let file_path = self.path.join(file_name);
        fs::write(&file_path, &value).map_err(|e| SeetleError::StorageError(e.to_string()))?;
        cache.insert(key.to_string(), value);
        Ok(())
    }

    async fn remove_item(&self, key: &str) -> Result<(), SeetleError> {
        let mut cache = self.cache.write().map_err(|e| SeetleError::OperationError(e.to_string()))?;
        let file_name = if let Some(ext) = &self.extension {
            format!("{}{}", key, ext)
        } else {
            key.to_string()
        };
        let file_path = self.path.join(file_name);
        if file_path.exists() {
            fs::remove_file(file_path).map_err(|e| SeetleError::StorageError(e.to_string()))?;
        }
        cache.remove(key);
        Ok(())
    }

    async fn list_items(&self) -> Result<Vec<String>, SeetleError> {
        let cache = self.cache.read().map_err(|e| SeetleError::OperationError(e.to_string()))?;
        Ok(cache.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_file_storage_extension() {
        let temp_dir = std::env::temp_dir().join("seetle-test-ext");
        if temp_dir.exists() {
            fs::remove_dir_all(&temp_dir).unwrap();
        }
        fs::create_dir_all(&temp_dir).unwrap();
        
        let storage = FileStorage::new_with_extension(&temp_dir, Some(".json".to_string())).unwrap();
        let key = "test-key";
        let data = b"json-data".to_vec();
        
        storage.set_item(key, data.clone()).await.unwrap();
        
        // Check if file exists with .json extension
        let file_path = temp_dir.join("test-key.json");
        assert!(file_path.exists());
        
        // Check if file without extension does NOT exist
        let no_ext_path = temp_dir.join("test-key");
        assert!(!no_ext_path.exists());
        
        // Retrieve and check
        let retrieved = storage.get_item(key).await.unwrap().unwrap();
        assert_eq!(data, retrieved);
        
        // List and check (should not have extension)
        let items = storage.list_items().await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "test-key");
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).unwrap();
    }
}
