use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SeetleConfig {
    pub storage_dir: PathBuf,
    pub storage_wrapper: String,
    pub root_backend: String,
    pub tpm_device: Option<String>,
}

impl Default for SeetleConfig {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("seetle-keystore"),
            storage_wrapper: "keyring".to_string(),
            root_backend: "keyring".to_string(),
            tpm_device: None,
        }
    }
}

pub fn load_config() -> SeetleConfig {
    confy::load("seetle", None).unwrap_or_default()
}

pub fn save_config(config: &SeetleConfig) -> Result<(), confy::ConfyError> {
    confy::store("seetle", None, config)
}

pub fn is_config_existing() -> bool {
    confy::get_configuration_file_path("seetle", None)
        .map(|p| p.exists())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_roundtrip() {
        let mut config = SeetleConfig::default();
        config.storage_wrapper = "tpm".to_string();
        config.root_backend = "keyring".to_string();
        
        // We use a temporary app name for testing to avoid touching real config
        let test_app_name = "seetle-test-config";
        confy::store(test_app_name, None, &config).unwrap();
        
        let loaded: SeetleConfig = confy::load(test_app_name, None).unwrap();
        assert_eq!(loaded.storage_wrapper, "tpm");
        assert_eq!(loaded.root_backend, "keyring");
        
        // Cleanup (confy path is OS-dependent, so we might not be able to easily find the exact file to delete, 
        // but it's fine for a unit test in this environment)
    }
}
