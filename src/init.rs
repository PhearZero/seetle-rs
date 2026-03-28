use std::sync::Arc;
use std::error::Error;
use log::{info, debug};

use crate::{Seetle, Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SecureStorage, HardwareBound};
use crate::config::SeetleConfig;
use crate::xhd::XHDBackend;
use crate::keyring::{KeyringBackend, KeyringStorage};
#[cfg(feature = "tpm")]
use crate::tpm::{TpmBackend, TpmStorage};
use crate::mock::MockBackend;
use crate::file::FileStorage;
use crate::memory::MemoryStorage;

pub async fn setup_seetle(config: &SeetleConfig) -> Result<Arc<dyn Seetle>, Box<dyn Error>> {
    let storage_dir = &config.storage_dir;
    let storage_wrapper = &config.storage_wrapper;
    let root_backend = &config.root_backend;
    #[allow(unused_variables)]
    let tpm_device = &config.tpm_device;

    // 1. Initialize base storage (FileStorage)
    let is_wrapped = storage_wrapper != "none";
    let storage_extension = match storage_wrapper.as_str() {
        "tpm" => Some(".tpm.enc".to_string()),
        "keyring" => Some(".keyring.enc".to_string()),
        "none" => Some(".json".to_string()),
        _ => Some(".enc".to_string()),
    };
    let base_storage = Arc::new(FileStorage::new_with_extension(storage_dir, storage_extension)?);

    #[cfg(feature = "tpm")]
    let tpm_context = if storage_wrapper == "tpm" || root_backend == "tpm" {
        Some(TpmBackend::create_context(tpm_device.as_deref())?)
    } else {
        None
    };

    // 2. Wrap storage if requested
    let secure_storage: Arc<dyn SecureStorage> = match storage_wrapper.as_str() {
        "tpm" => {
            #[cfg(feature = "tpm")]
            {
                debug!("Using TPM-wrapped storage");
                Arc::new(TpmStorage::new(base_storage, tpm_context.clone().unwrap())?)
            }
            #[cfg(not(feature = "tpm"))]
            {
                return Err("TPM support not enabled".into());
            }
        },
        "keyring" => {
            debug!("Using Keyring-wrapped storage");
            let storage = KeyringStorage::new(base_storage, "seetle", "master-key")?;
            storage.initialize().await?;
            Arc::new(storage)
        },
        _ => base_storage,
    };

    // 3. Initialize root backend
    let root_backend_inst: Arc<dyn Seetle> = match root_backend.as_str() {
        "tpm" => {
            #[cfg(feature = "tpm")]
            {
                debug!("Using TPM as root backend");
                let tpm_metadata_dir = storage_dir.join("tpm-root");
                let root_ext = if is_wrapped { ".tpm.enc".to_string() } else { ".tpm.json".to_string() };
                let tpm_storage_base = Arc::new(FileStorage::new_with_extension(tpm_metadata_dir, Some(root_ext))?);
                let tpm_storage: Arc<dyn SecureStorage> = if is_wrapped {
                    match storage_wrapper.as_str() {
                        "tpm" => {
                            Arc::new(TpmStorage::new(tpm_storage_base, tpm_context.clone().unwrap())?)
                        },
                        "keyring" => {
                            let storage = KeyringStorage::new(tpm_storage_base, "seetle", "master-key")?;
                            storage.initialize().await?;
                            Arc::new(storage)
                        },
                        _ => tpm_storage_base,
                    }
                } else {
                    tpm_storage_base
                };
                Arc::new(TpmBackend::new(tpm_storage, tpm_context.unwrap())?)
            }
            #[cfg(not(feature = "tpm"))]
            {
                return Err("TPM support not enabled".into());
            }
        },
        "keyring" => {
            debug!("Using Keyring as root backend");
            let keyring_metadata_dir = storage_dir.join("keyring-root");
            let root_ext = if is_wrapped { ".keyring.enc".to_string() } else { ".keyring.json".to_string() };
            let keyring_storage_base = Arc::new(FileStorage::new_with_extension(keyring_metadata_dir, Some(root_ext))?);
            let keyring_storage: Arc<dyn SecureStorage> = if is_wrapped {
                match storage_wrapper.as_str() {
                    "tpm" => {
                        #[cfg(feature = "tpm")]
                        {
                            Arc::new(TpmStorage::new(keyring_storage_base, tpm_context.clone().unwrap())?)
                        }
                        #[cfg(not(feature = "tpm"))]
                        {
                            return Err("TPM support not enabled".into());
                        }
                    },
                    "keyring" => {
                        let storage = KeyringStorage::new(keyring_storage_base, "seetle", "master-key")?;
                        storage.initialize().await?;
                        Arc::new(storage)
                    },
                    _ => keyring_storage_base,
                }
            } else {
                keyring_storage_base
            };
            Arc::new(KeyringBackend::new(keyring_storage))
        },
        _ => {
            debug!("Using MockBackend as root backend");
            let mock_storage = Arc::new(MemoryStorage::new());
            Arc::new(MockBackend::new(mock_storage))
        }
    };

    // 4. Ensure master key exists in root backend if it's the root for XHD
    let master_key_id = "seetle-master-seed";
    let master_alg = Algorithm::Generic { name: "MasterSeed".into() };

    match root_backend_inst.derive_bits(master_alg.clone(), KeyOrIdentifier::Identifier(master_key_id.into()), 512).await {
        Err(crate::SeetleError::KeyNotFound) => {
            let root_metadata_dir = match root_backend.as_str() {
                "tpm" => Some(storage_dir.join("tpm-root")),
                "keyring" => Some(storage_dir.join("keyring-root")),
                _ => None,
            };

            if let Some(dir) = root_metadata_dir {
                if dir.exists() && std::fs::read_dir(&dir)?.any(|e| e.is_ok()) {
                     return Err(format!("Master seed not found in root backend ({}), but metadata exists. This indicates a persistence issue (e.g. keyring cleared or TPM hierarchy mismatch).", root_backend).into());
                }
            }

            info!("Master seed not found in root backend, generating it...");
            root_backend_inst.generate_key(
                master_alg.clone(),
                true,
                Some(Bindings {
                    identifier: master_key_id.into(),
                    hardware_bound: HardwareBound::Yes,
                    ..Default::default()
                }),
                vec![KeyUsage::DeriveBits]
            ).await?;
        }
        Err(e) => {
            return Err(format!("Error while checking/generating master seed: {:?}", e).into());
        }
        Ok(_) => {
            // Master seed exists
        }
    }

    // 5. Initialize XHDBackend
    let xhd_backend = Arc::new(XHDBackend::new_with_backend(
        secure_storage,
        root_backend_inst,
        master_key_id.into(),
        Algorithm::Generic { name: "MasterSeed".into() }
    ));

    Ok(xhd_backend)
}
