use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Backend, Seetle, SecureStorage};
use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

/// Nordic backend using CryptoCell and PSA Crypto API.
///
/// This backend leverages the Arm CryptoCell hardware accelerator available on
/// many Nordic Semiconductor SoCs (like nRF52840, nRF9160, nRF5340).
/// It interfaces with the PSA Crypto API provided by the nRF Connect SDK.
pub struct NordicBackend {
    storage: Arc<dyn SecureStorage>,
}

#[derive(Serialize, Deserialize)]
struct KeyMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
    psa_id: PsaKeyId,
}

impl NordicBackend {
    pub fn new(storage: Arc<dyn SecureStorage>) -> Self {
        Self { storage }
    }

    /// Initialize the PSA Crypto subsystem.
    pub fn init(&self) -> Result<(), SeetleError> {
        let status = unsafe { psa_crypto_init() };
        if status == PSA_SUCCESS {
            Ok(())
        } else {
            Err(map_psa_error(status))
        }
    }

    async fn get_metadata(&self, identifier: &str) -> Result<KeyMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|_e| SeetleError::DataError)
    }

    fn check_usage(&self, metadata: &KeyMetadata, usage: KeyUsage) -> Result<(), SeetleError> {
        if metadata.usages.contains(&usage) {
            Ok(())
        } else {
            Err(SeetleError::OperationError(format!("Key does not support usage: {:?}", usage)))
        }
    }
}

impl Backend for NordicBackend {
    fn seetle(&self) -> &dyn Seetle {
        self
    }
}

// PSA Crypto API types and bindings
type PsaStatus = i32;
type PsaKeyId = u32;
type PsaAlgorithm = u32;
type PsaKeyType = u32;
type PsaKeyUsage = u32;

#[repr(C)]
pub struct PsaKeyAttributes {
    _opaque: [u8; 64],
}

unsafe extern "C" {
    fn psa_crypto_init() -> PsaStatus;
    fn psa_generate_key(attributes: *const PsaKeyAttributes, key_id: *mut PsaKeyId) -> PsaStatus;
    fn psa_destroy_key(key_id: PsaKeyId) -> PsaStatus;
    fn psa_sign_message(
        key_id: PsaKeyId,
        alg: PsaAlgorithm,
        input: *const u8,
        input_length: usize,
        signature: *mut u8,
        signature_size: usize,
        signature_length: *mut usize,
    ) -> PsaStatus;
    fn psa_verify_message(
        key_id: PsaKeyId,
        alg: PsaAlgorithm,
        input: *const u8,
        input_length: usize,
        signature: *const u8,
        signature_length: usize,
    ) -> PsaStatus;
    
    fn psa_set_key_usage_flags(attributes: *mut PsaKeyAttributes, usages: PsaKeyUsage);
    fn psa_set_key_algorithm(attributes: *mut PsaKeyAttributes, alg: PsaAlgorithm);
    fn psa_set_key_type(attributes: *mut PsaKeyAttributes, key_type: PsaKeyType);
    fn psa_set_key_bits(attributes: *mut PsaKeyAttributes, bits: usize);
    fn psa_set_key_lifetime(attributes: *mut PsaKeyAttributes, lifetime: u32);
    #[allow(dead_code)]
    fn psa_set_key_id(attributes: *mut PsaKeyAttributes, id: PsaKeyId);
}

const PSA_SUCCESS: PsaStatus = 0;

// PSA Usages
#[allow(dead_code)]
const PSA_KEY_USAGE_EXPORT: PsaKeyUsage = 0x00000001;
const PSA_KEY_USAGE_ENCRYPT: PsaKeyUsage = 0x00000100;
const PSA_KEY_USAGE_DECRYPT: PsaKeyUsage = 0x00000200;
const PSA_KEY_USAGE_SIGN_MESSAGE: PsaKeyUsage = 0x00000400;
const PSA_KEY_USAGE_VERIFY_MESSAGE: PsaKeyUsage = 0x00000800;
const PSA_KEY_USAGE_SIGN_HASH: PsaKeyUsage = 0x00001000;
const PSA_KEY_USAGE_VERIFY_HASH: PsaKeyUsage = 0x00002000;
const PSA_KEY_USAGE_DERIVE: PsaKeyUsage = 0x00004000;

// PSA Algorithms (Simplified)
#[allow(dead_code)]
const PSA_ALG_ANY_HASH: PsaAlgorithm = 0x02000000;
#[allow(dead_code)]
const PSA_ALG_SHA_256: PsaAlgorithm = 0x02000009;
const PSA_ALG_ECDSA_ANY: PsaAlgorithm = 0x06000600;
const PSA_ALG_ECDSA_SHA_256: PsaAlgorithm = 0x06000609;
const PSA_ALG_RSA_PSS_ANY: PsaAlgorithm = 0x06000400;
const PSA_ALG_RSA_PSS_SHA_256: PsaAlgorithm = 0x06000409;
const PSA_ALG_GCM: PsaAlgorithm = 0x04400100;

// PSA Key Types
const PSA_KEY_TYPE_ECC_KEY_PAIR_SECP256R1: PsaKeyType = 0x710012;
const PSA_KEY_TYPE_RSA_KEY_PAIR: PsaKeyType = 0x7001;
const PSA_KEY_TYPE_AES: PsaKeyType = 0x2400;

// PSA Lifetimes
const PSA_KEY_LIFETIME_VOLATILE: u32 = 0x00000000;
const PSA_KEY_LIFETIME_PERSISTENT: u32 = 0x00000001;

fn map_psa_error(status: PsaStatus) -> SeetleError {
    match status {
        -133 => SeetleError::AccessDenied,
        -134 => SeetleError::NotSupported,
        -135 => SeetleError::DataError,
        -136 => SeetleError::KeyNotFound,
        -140 => SeetleError::KeyNotFound,
        -149 => SeetleError::DataError,
        _ => SeetleError::OperationError(format!("PSA error: {}", status)),
    }
}

fn map_key_usage(usages: &[KeyUsage]) -> PsaKeyUsage {
    let mut psa_usages = 0;
    for usage in usages {
        match usage {
            KeyUsage::Encrypt => psa_usages |= PSA_KEY_USAGE_ENCRYPT,
            KeyUsage::Decrypt => psa_usages |= PSA_KEY_USAGE_DECRYPT,
            KeyUsage::Sign => psa_usages |= PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH,
            KeyUsage::Verify => psa_usages |= PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH,
            KeyUsage::DeriveKey | KeyUsage::DeriveBits => psa_usages |= PSA_KEY_USAGE_DERIVE,
            _ => {}
        }
    }
    psa_usages
}

fn map_algorithm(alg: &Algorithm) -> PsaAlgorithm {
    match alg {
        Algorithm::Ecdsa { hash, .. } => {
            match hash.as_deref() {
                Some("SHA-256") => PSA_ALG_ECDSA_SHA_256,
                _ => PSA_ALG_ECDSA_ANY,
            }
        }
        Algorithm::RsaPss { hash, .. } => {
            if hash == "SHA-256" { PSA_ALG_RSA_PSS_SHA_256 } else { PSA_ALG_RSA_PSS_ANY }
        }
        Algorithm::AesGcm { .. } => PSA_ALG_GCM,
        _ => 0,
    }
}

fn map_key_type(alg: &Algorithm) -> PsaKeyType {
    match alg {
        Algorithm::Ecdsa { named_curve, .. } => {
            match named_curve.as_str() {
                "P-256" => PSA_KEY_TYPE_ECC_KEY_PAIR_SECP256R1,
                _ => 0,
            }
        }
        Algorithm::RsaPss { .. } => PSA_KEY_TYPE_RSA_KEY_PAIR,
        Algorithm::AesGcm { .. } => PSA_KEY_TYPE_AES,
        _ => 0,
    }
}

fn get_key_bits(alg: &Algorithm) -> usize {
    match alg {
        Algorithm::Ecdsa { named_curve, .. } => {
            match named_curve.as_str() {
                "P-256" => 256,
                "P-384" => 384,
                "P-521" => 521,
                _ => 0,
            }
        }
        Algorithm::RsaPss { modulus_length, .. } => *modulus_length as usize,
        Algorithm::AesGcm { length, .. } => *length as usize,
        _ => 0,
    }
}

#[async_trait]
impl Seetle for NordicBackend {
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        if let Some(b) = bindings {
            if b.hardware_bound && extractable {
                return Err(SeetleError::OperationError(
                    "Hardware bound keys cannot be extractable".into(),
                ));
            }

            let mut attributes = PsaKeyAttributes { _opaque: [0; 64] };
            let psa_usage = map_key_usage(&key_usages);
            let psa_alg = map_algorithm(&algorithm);
            let psa_type = map_key_type(&algorithm);

            unsafe {
                psa_set_key_usage_flags(&mut attributes, psa_usage);
                psa_set_key_algorithm(&mut attributes, psa_alg);
                psa_set_key_type(&mut attributes, psa_type);
                psa_set_key_bits(&mut attributes, get_key_bits(&algorithm));
                if b.hardware_bound {
                    psa_set_key_lifetime(&mut attributes, PSA_KEY_LIFETIME_PERSISTENT);
                } else {
                    psa_set_key_lifetime(&mut attributes, PSA_KEY_LIFETIME_VOLATILE);
                }
            }

            let mut psa_id: PsaKeyId = 0;
            let status = unsafe { psa_generate_key(&attributes, &mut psa_id) };
            
            // If we are in a mock environment (like during tests without actual PSA)
            // we might get an error. To keep it robust but functional for dev, 
            // we should probably handle it. But the user said "do not mock".
            // So we should fail if PSA fails.
            if status != PSA_SUCCESS {
                return Err(map_psa_error(status));
            }

            let metadata = KeyMetadata {
                bindings: b.clone(),
                algorithm,
                usages: key_usages,
                psa_id,
            };
            
            let metadata_bytes = serde_json::to_vec(&metadata)
                .map_err(|e| SeetleError::OperationError(e.to_string()))?;
            self.storage.set_item(&b.identifier, metadata_bytes).await?;

            Ok(KeyOrIdentifier::Identifier(b.identifier))
        } else {
            // For non-hardware bound keys without bindings, we could still use PSA with volatile lifetime
            // and return a CryptoKey.
            Err(SeetleError::NotSupported)
        }
    }

    async fn update_key(
        &self,
        identifier: String,
        new_bindings: Bindings,
    ) -> Result<(), SeetleError> {
        let mut metadata = self.get_metadata(&identifier).await?;
        if !metadata.bindings.updatable {
             return Err(SeetleError::OperationError("Key is not updatable".into()));
        }
        metadata.bindings = new_bindings;
        let metadata_bytes = serde_json::to_vec(&metadata)
            .map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, metadata_bytes).await?;
        Ok(())
    }

    async fn delete_key(
        &self,
        identifier: String,
    ) -> Result<(), SeetleError> {
        let metadata = self.get_metadata(&identifier).await?;
        unsafe { psa_destroy_key(metadata.psa_id) };
        self.storage.remove_item(&identifier).await?;
        Ok(())
    }

    async fn sign(
        &self,
        algorithm: Algorithm,
        key: KeyOrIdentifier,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        match key {
            KeyOrIdentifier::Identifier(id) => {
                let metadata = self.get_metadata(&id).await?;
                self.check_usage(&metadata, KeyUsage::Sign)?;
                
                let psa_alg = map_algorithm(&algorithm);
                let mut signature = vec![0u8; 64]; // Enough for P-256
                let mut signature_length: usize = 0;
                
                let status = unsafe {
                    psa_sign_message(
                        metadata.psa_id,
                        psa_alg,
                        data.as_ptr(),
                        data.len(),
                        signature.as_mut_ptr(),
                        signature.len(),
                        &mut signature_length,
                    )
                };
                
                if status == PSA_SUCCESS {
                    signature.truncate(signature_length);
                    Ok(signature)
                } else {
                    Err(map_psa_error(status))
                }
            }
            KeyOrIdentifier::Key(_) => Err(SeetleError::NotSupported),
        }
    }

    async fn verify(
        &self,
        algorithm: Algorithm,
        key: KeyOrIdentifier,
        signature: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<bool, SeetleError> {
        match key {
            KeyOrIdentifier::Identifier(id) => {
                let metadata = self.get_metadata(&id).await?;
                self.check_usage(&metadata, KeyUsage::Verify)?;
                
                let psa_alg = map_algorithm(&algorithm);
                let status = unsafe {
                    psa_verify_message(
                        metadata.psa_id,
                        psa_alg,
                        data.as_ptr(),
                        data.len(),
                        signature.as_ptr(),
                        signature.len(),
                    )
                };
                
                if status == PSA_SUCCESS {
                    Ok(true)
                } else if status == -149 { // INVALID_SIGNATURE
                    Ok(false)
                } else {
                    Err(map_psa_error(status))
                }
            }
            KeyOrIdentifier::Key(_) => Err(SeetleError::NotSupported),
        }
    }

    async fn encrypt(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        if let KeyOrIdentifier::Identifier(id) = key {
            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::Encrypt)?;
        }
        Err(SeetleError::NotSupported)
    }

    async fn decrypt(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        if let KeyOrIdentifier::Identifier(id) = key {
            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::Decrypt)?;
        }
        Err(SeetleError::NotSupported)
    }

    async fn digest(
        &self,
        _algorithm: Algorithm,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn import_key(
        &self,
        _format: String,
        _key_data: Vec<u8>,
        _algorithm: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn export_key(
        &self,
        _format: String,
        _key: CryptoKey,
    ) -> Result<Vec<u8>, SeetleError> {
        // Hardware bound keys are not exportable by definition in this context
        Err(SeetleError::NotSupported)
    }

    async fn derive_key(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        _derived_key_type: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        if let KeyOrIdentifier::Identifier(id) = key {
            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::DeriveKey)?;
        }
        Err(SeetleError::NotSupported)
    }

    async fn derive_bits(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        _length: u32,
    ) -> Result<Vec<u8>, SeetleError> {
        if let KeyOrIdentifier::Identifier(id) = key {
            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::DeriveBits)?;
        }
        Err(SeetleError::NotSupported)
    }

    async fn wrap_key(
        &self,
        _format: String,
        _key: CryptoKey,
        wrapping_key: KeyOrIdentifier,
        _wrap_algorithm: Algorithm,
    ) -> Result<Vec<u8>, SeetleError> {
        if let KeyOrIdentifier::Identifier(id) = wrapping_key {
            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::WrapKey)?;
        }
        Err(SeetleError::NotSupported)
    }

    async fn unwrap_key(
        &self,
        _format: String,
        _wrapped_key: Vec<u8>,
        unwrapping_key: KeyOrIdentifier,
        _unwrap_algorithm: Algorithm,
        _unwrapped_key_algorithm: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError> {
        if let KeyOrIdentifier::Identifier(id) = unwrapping_key {
            let metadata = self.get_metadata(&id).await?;
            self.check_usage(&metadata, KeyUsage::UnwrapKey)?;
        }
        Err(SeetleError::NotSupported)
    }
}

#[cfg(test)]
mod nordic_tests {
    use super::*;
    use crate::backends::mock::MemoryStorage;

    #[tokio::test]
    async fn test_nordic_usage_enforcement() {
        let storage = Arc::new(MemoryStorage::new());
        let backend = NordicBackend::new(storage.clone());
        
        let bindings = Bindings {
            identifier: "test-key".into(),
            hardware_bound: true,
            ..Default::default()
        };
        let metadata = KeyMetadata {
            bindings: bindings.clone(),
            algorithm: Algorithm::Ecdsa { 
                name: "ECDSA".into(), 
                named_curve: "P-256".into(), 
                hash: Some("SHA-256".into()) 
            },
            usages: vec![KeyUsage::Sign],
            psa_id: 123,
        };
        
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap();
        storage.set_item("test-key", metadata_bytes).await.unwrap();
        
        // Test usage validation
        let retrieved_metadata = backend.get_metadata("test-key").await.unwrap();
        assert!(backend.check_usage(&retrieved_metadata, KeyUsage::Sign).is_ok());
        let err = backend.check_usage(&retrieved_metadata, KeyUsage::Verify);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Key does not support usage"));
    }
}
