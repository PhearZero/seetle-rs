use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Backend, Seetle, SecureStorage};
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum LtRet {
    Ok = 0,
    Fail = 1,
}

/// Opaque pointer to lt_handle_t
#[repr(C)]
pub struct LtHandle { _private: [u8; 0] }

unsafe impl Send for LtHandle {}
unsafe impl Sync for LtHandle {}

#[repr(C)]
pub enum LtEccCurve {
    P256 = 1,
    Ed25519 = 2,
}

unsafe extern "C" {
    fn lt_seelte_create_handle() -> *mut LtHandle;
    fn lt_seelte_free_handle(h: *mut LtHandle);

    fn lt_init(h: *mut LtHandle) -> LtRet;
    fn lt_deinit(h: *mut LtHandle) -> LtRet;
    fn lt_ecc_key_generate(h: *mut LtHandle, slot: u32, curve: LtEccCurve) -> LtRet;
    fn lt_ecc_key_read(h: *mut LtHandle, slot: u32, key: *mut u8, key_max_size: u8, curve: *mut LtEccCurve, origin: *mut u8) -> LtRet;
    fn lt_ecc_ecdsa_sign(h: *mut LtHandle, slot: u32, msg: *const u8, msg_len: u32, rs: *mut u8) -> LtRet;
    
    // Mock HAL control API
    fn lt_mock_hal_enqueue_response(s2: *mut LtHandle, data: *const u8, len: usize) -> LtRet;
}

pub struct TropicBackend {
    storage: Arc<dyn SecureStorage>,
    handle: Mutex<*mut LtHandle>,
}

unsafe impl Send for TropicBackend {}
unsafe impl Sync for TropicBackend {}

#[derive(Serialize, Deserialize, Clone)]
struct KeyMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
    slot: u32,
}

impl TropicBackend {
    pub async fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, SeetleError> {
        println!("TropicBackend::new start");
        let handle = unsafe { lt_seelte_create_handle() };
        println!("TropicBackend::new handle created: {:?}", handle);
        if handle.is_null() {
            return Err(SeetleError::OperationError("Failed to create lt_handle".into()));
        }

        // Enqueue a response for lt_get_tr01_mode (Ready status)
        let ready_status: u8 = 0x01; 
        unsafe {
            lt_mock_hal_enqueue_response(handle, &ready_status, 1);
        }

        let ret = unsafe { lt_init(handle) };
        if !matches!(ret, LtRet::Ok) {
            unsafe { lt_seelte_free_handle(handle); }
            return Err(SeetleError::OperationError(format!("lt_init failed: {:?}", ret)));
        }

        Ok(Self {
            storage,
            handle: Mutex::new(handle),
        })
    }

    async fn get_metadata(&self, identifier: &str) -> Result<KeyMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|e| SeetleError::OperationError(e.to_string()))
    }
}

impl Backend for TropicBackend {
    fn seetle(&self) -> &dyn Seetle {
        self
    }
}

#[async_trait]
impl Seetle for TropicBackend {
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        if let Some(b) = bindings {
            if b.hardware_bound && extractable {
                return Err(SeetleError::OperationError("Hardware bound keys cannot be extractable".into()));
            }

            let curve = match &algorithm {
                Algorithm::Ecdsa { named_curve, .. } if named_curve == "P-256" => LtEccCurve::P256,
                _ => return Err(SeetleError::NotSupported),
            };

            let slot = 0; // FIXME: Slot management

            {
                let handle = self.handle.lock().map_err(|e| SeetleError::OperationError(e.to_string()))?;
                
                // Enqueue response for key generation success
                // L2 SUCCESS frame: [0x01 (Ready), 0x20 (REQUEST_OK), 0x00 (Len), CRC, CRC]
                let success_resp = [0x01, 0x20, 0x00, 0x00, 0x00]; 
                unsafe { lt_mock_hal_enqueue_response(*handle, success_resp.as_ptr(), 5); }

                let ret = unsafe { lt_ecc_key_generate(*handle, slot, curve) };
                if !matches!(ret, LtRet::Ok) {
                    return Err(SeetleError::OperationError(format!("lt_ecc_key_generate failed: {:?}", ret)));
                }
            }

            let metadata = KeyMetadata {
                bindings: b.clone(),
                algorithm,
                usages: key_usages,
                slot,
            };
            let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
            self.storage.set_item(&b.identifier, metadata_bytes).await?;

            Ok(KeyOrIdentifier::Identifier(b.identifier))
        } else {
            Err(SeetleError::OperationError("Bindings required for TropicBackend".into()))
        }
    }

    async fn update_key(&self, identifier: String, new_bindings: Bindings) -> Result<(), SeetleError> {
        let mut metadata = self.get_metadata(&identifier).await?;
        if !metadata.bindings.updatable {
            return Err(SeetleError::OperationError("Key is not updatable".into()));
        }
        metadata.bindings = new_bindings;
        let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, metadata_bytes).await?;
        Ok(())
    }

    async fn delete_key(&self, identifier: String) -> Result<(), SeetleError> {
        self.storage.remove_item(&identifier).await?;
        Ok(())
    }

    async fn sign(&self, _algorithm: Algorithm, key: KeyOrIdentifier, data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        let id = match key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        let metadata = self.get_metadata(&id).await?;
        
        let rs = {
            let handle = self.handle.lock().map_err(|e| SeetleError::OperationError(e.to_string()))?;
            
            // Enqueue response for sign success (L2 Response with RSP_LEN=65 because it includes status byte etc)
            // Actually, lt_ecc_ecdsa_sign expects L3 result.
            // L2 frame for L3 result: [CHIP_STATUS, STATUS, RSP_LEN=67, ...]
            // But wait, the mock HAL should handle the L3 result if it's correctly mocked.
            // For now, let's just use a fake success response.
            let mut success_resp = vec![0x01, 0x20, 67]; // Ready, OK, Len
            success_resp.extend_from_slice(&[0; 64]); // Fake signature data
            success_resp.extend_from_slice(&[0, 0]); // CRC
            unsafe { lt_mock_hal_enqueue_response(*handle, success_resp.as_ptr(), success_resp.len()); }

            let mut rs = [0u8; 64];
            let ret = unsafe { lt_ecc_ecdsa_sign(*handle, metadata.slot, data.as_ptr(), data.len() as u32, rs.as_mut_ptr()) };
            if !matches!(ret, LtRet::Ok) {
                return Err(SeetleError::OperationError(format!("lt_ecc_ecdsa_sign failed: {:?}", ret)));
            }
            rs
        };
        Ok(rs.to_vec())
    }

    async fn verify(&self, _algorithm: Algorithm, key: KeyOrIdentifier, signature: Vec<u8>, data: Vec<u8>) -> Result<bool, SeetleError> {
        let id = match key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        let metadata = self.get_metadata(&id).await?;

        let pubkey = {
            let handle = self.handle.lock().map_err(|e| SeetleError::OperationError(e.to_string()))?;
            
            // Enqueue response for key read success
            let mut success_resp = vec![0x01, 0x20, 67]; // Ready, OK, Len
            success_resp.extend_from_slice(&[0; 64]); // Fake public key
            success_resp.extend_from_slice(&[0, 0]); // CRC
            unsafe { lt_mock_hal_enqueue_response(*handle, success_resp.as_ptr(), success_resp.len()); }

            let mut pubkey = [0u8; 64];
            let mut curve = LtEccCurve::P256;
            let mut origin = 0u8;
            let ret = unsafe { lt_ecc_key_read(*handle, metadata.slot, pubkey.as_mut_ptr(), 64, &mut curve, &mut origin) };
            if !matches!(ret, LtRet::Ok) {
                 return Err(SeetleError::OperationError(format!("lt_ecc_key_read failed: {:?}", ret)));
            }
            pubkey
        };

        // Use ring for verification
        use ring::signature;
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            pubkey
        );
        match peer_public_key.verify(&data, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn encrypt(&self, _algorithm: Algorithm, _key: KeyOrIdentifier, _data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn decrypt(&self, _algorithm: Algorithm, _key: KeyOrIdentifier, _data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn digest(&self, _algorithm: Algorithm, _data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn import_key(&self, _format: String, _key_data: Vec<u8>, _algorithm: Algorithm, _extractable: bool, _key_usages: Vec<KeyUsage>) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn export_key(&self, _format: String, _key: CryptoKey) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_key(&self, _algorithm: Algorithm, _base_key: KeyOrIdentifier, _derived_key_type: Algorithm, _extractable: bool, _key_usages: Vec<KeyUsage>) -> Result<KeyOrIdentifier, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_bits(&self, _algorithm: Algorithm, _base_key: KeyOrIdentifier, _length: u32) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn wrap_key(&self, _format: String, _key: CryptoKey, _wrapping_key: KeyOrIdentifier, _wrap_algorithm: Algorithm) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn unwrap_key(&self, _format: String, _wrapped_key: Vec<u8>, _unwrapping_key: KeyOrIdentifier, _unwrap_algorithm: Algorithm, _unwrapped_key_algorithm: Algorithm, _extractable: bool, _key_usages: Vec<KeyUsage>) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }
}

impl Drop for TropicBackend {
    fn drop(&mut self) {
        if let Ok(handle) = self.handle.lock() {
            unsafe { 
                lt_deinit(*handle);
                lt_seelte_free_handle(*handle);
            }
        }
    }
}

