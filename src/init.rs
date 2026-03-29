use std::sync::Arc;
use std::error::Error;
use log::{info, debug};

use crate::{Seetle, Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SecureStorage, HardwareBound};
use crate::config::SeetleConfig;
use crate::xhd::XHDBackend;
use crate::keyring::{KeyringBackend, KeyringStorage};
#[cfg(feature = "tpm")]
use crate::tpm::{TpmBackend, TpmStorage};
#[cfg(feature = "nordic")]
use crate::nordic::NordicBackend;
#[cfg(feature = "tropic")]
use crate::tropic::TropicBackend;
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::secure_env::SecureEnvBackend;
use crate::mock::MockBackend;
use crate::file::FileStorage;

pub async fn setup_seetle(config: &SeetleConfig) -> Result<Arc<dyn Seetle>, Box<dyn Error>> {
    let storage_dir = &config.storage_dir;
    let storage_wrapper = &config.storage_wrapper;
    let root_backend = &config.root_backend;
    #[allow(unused_variables)]
    let tpm_device = &config.tpm_device;

    // 1. Initialize base storage (FileStorage)
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
                Arc::new(TpmBackend::new(secure_storage.clone(), tpm_context.unwrap())?)
            }
            #[cfg(not(feature = "tpm"))]
            {
                return Err("TPM support not enabled".into());
            }
        },
        "keyring" => {
            debug!("Using Keyring as root backend");
            Arc::new(KeyringBackend::new(secure_storage.clone()))
        },
        "nordic" => {
            #[cfg(feature = "nordic")]
            {
                debug!("Using Nordic as root backend");
                let backend = Arc::new(NordicBackend::new(secure_storage.clone()));
                // Nordic backend might need initialization, but let's keep it simple for now
                // as per current NordicBackend implementation.
                backend
            }
            #[cfg(not(feature = "nordic"))]
            {
                return Err("Nordic support not enabled".into());
            }
        },
        "tropic" => {
            #[cfg(feature = "tropic")]
            {
                debug!("Using Tropic as root backend");
                Arc::new(TropicBackend::new(secure_storage.clone())?)
            }
            #[cfg(not(feature = "tropic"))]
            {
                return Err("Tropic support not enabled".into());
            }
        },
        "secure-env" | "hpke" => {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                debug!("Using SecureEnv as root backend");
                Arc::new(SecureEnvBackend::new(secure_storage.clone()))
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                // If the user said "hpke" they might mean a mock backend that supports HPKE?
                // But for now, let's treat it as not supported on this platform if it's secure-env.
                if root_backend == "hpke" {
                     debug!("Using MockBackend for HPKE root");
                     Arc::new(MockBackend::new(secure_storage.clone()))
                } else {
                    return Err("SecureEnv support only available on Android or iOS".into());
                }
            }
        },
        _ => {
            debug!("Using MockBackend as root backend");
            Arc::new(MockBackend::new(secure_storage.clone()))
        }
    };

    // 4. Ensure master key exists in root backend if it's the root for XHD
    let master_key_id = "seetle-master-seed";
    let master_alg = Algorithm::Generic { name: "MasterSeed".into() };

    match root_backend_inst.derive_bits(master_alg.clone(), KeyOrIdentifier::Identifier(master_key_id.into()), 512).await {
        Err(crate::SeetleError::KeyNotFound) => {
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
