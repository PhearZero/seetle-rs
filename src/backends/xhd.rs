use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Backend, Seetle, SecureStorage};
use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use xhd_wallet_api::{XPrv, DerivationScheme, KeyContext, key_gen, Signature};
use std::str::FromStr;

/// A backend that uses xHD-Wallet-API for hierarchical deterministic Ed25519 keys.
pub struct XHDBackend {
    storage: Arc<dyn SecureStorage>,
    root_key: XPrv,
}

#[derive(Serialize, Deserialize, Clone)]
struct XHDMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
    context: String,
    account: u32,
    key_index: u32,
    scheme: String,
}

impl XHDBackend {
    pub fn new(storage: Arc<dyn SecureStorage>, root_key: XPrv) -> Self {
        Self {
            storage,
            root_key,
        }
    }

    async fn get_metadata(&self, identifier: &str) -> Result<XHDMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|e| SeetleError::OperationError(e.to_string()))
    }

    fn parse_xhd_params(name: &str) -> Option<(KeyContext, u32, u32, DerivationScheme)> {
        // Expected format: "XHD:<Context>:<Account>:<Index>:<Scheme>"
        // e.g. "XHD:Address:0:0:Peikert"
        if !name.starts_with("XHD:") {
            return None;
        }
        let parts: Vec<&str> = name.split(':').collect();
        if parts.len() != 5 {
            return None;
        }

        let context = match parts[1] {
            "Address" => KeyContext::Address,
            "Identity" => KeyContext::Identity,
            _ => return None,
        };

        let account = u32::from_str(parts[2]).ok()?;
        let index = u32::from_str(parts[3]).ok()?;

        let scheme = match parts[4] {
            "Peikert" => DerivationScheme::Peikert,
            "V2" => DerivationScheme::V2,
            _ => return None,
        };

        Some((context, account, index, scheme))
    }
}

impl Backend for XHDBackend {
    fn seetle(&self) -> &dyn Seetle {
        self
    }
}

#[async_trait]
impl Seetle for XHDBackend {
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        let (context_enum, account, key_index, scheme_enum) = match &algorithm {
            Algorithm::Ed25519 { name } => {
                Self::parse_xhd_params(name).ok_or(SeetleError::NotSupported)?
            }
            Algorithm::Generic { name } => {
                Self::parse_xhd_params(name).ok_or(SeetleError::NotSupported)?
            }
            _ => return Err(SeetleError::NotSupported),
        };

        if let Some(b) = bindings {
            if b.hardware_bound && extractable {
                return Err(SeetleError::OperationError("Hardware bound keys cannot be extractable".into()));
            }

            let context_str = match context_enum {
                KeyContext::Address => "Address",
                KeyContext::Identity => "Identity",
            };
            let scheme_str = match scheme_enum {
                DerivationScheme::Peikert => "Peikert",
                DerivationScheme::V2 => "V2",
            };

            let metadata = XHDMetadata {
                bindings: b.clone(),
                algorithm: algorithm.clone(),
                usages: key_usages,
                context: context_str.to_string(),
                account,
                key_index,
                scheme: scheme_str.to_string(),
            };

            let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
            self.storage.set_item(&b.identifier, metadata_bytes).await?;

            Ok(KeyOrIdentifier::Identifier(b.identifier))
        } else {
            Err(SeetleError::OperationError("Bindings required for XHDBackend".into()))
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

        let context = match metadata.context.as_str() {
            "Address" => KeyContext::Address,
            "Identity" => KeyContext::Identity,
            _ => return Err(SeetleError::DataError),
        };
        let scheme = match metadata.scheme.as_str() {
            "Peikert" => DerivationScheme::Peikert,
            "V2" => DerivationScheme::V2,
            _ => return Err(SeetleError::DataError),
        };

        let derived_xprv = key_gen(&self.root_key, context, metadata.account, metadata.key_index, scheme)
            .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;

        let signature: Signature<Vec<u8>> = derived_xprv.sign(&data);
        Ok(signature.to_bytes().to_vec())
    }

    async fn verify(&self, _algorithm: Algorithm, key: KeyOrIdentifier, signature: Vec<u8>, data: Vec<u8>) -> Result<bool, SeetleError> {
        let id = match key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        let metadata = self.get_metadata(&id).await?;

        let context = match metadata.context.as_str() {
            "Address" => KeyContext::Address,
            "Identity" => KeyContext::Identity,
            _ => return Err(SeetleError::DataError),
        };
        let scheme = match metadata.scheme.as_str() {
            "Peikert" => DerivationScheme::Peikert,
            "V2" => DerivationScheme::V2,
            _ => return Err(SeetleError::DataError),
        };

        let derived_xprv = key_gen(&self.root_key, context, metadata.account, metadata.key_index, scheme)
            .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;
        let xpub = derived_xprv.public();

        let sig = Signature::<u8>::from_slice(&signature)
            .map_err(|_| SeetleError::DataError)?;

        Ok(xpub.verify(&data, &sig))
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

#[cfg(test)]
mod xhd_tests {
    use super::*;
    use crate::storage::{MemoryStorage, TpmStorage};

    const SEED: [u8; 64] = [0x42; 64];

    #[tokio::test]
    async fn test_xhd_backend_derivation_and_sign() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle = backend.seetle();

        // 1. Generate (derive) a key
        let algorithm = Algorithm::Ed25519 {
            name: "XHD:Address:0:0:Peikert".into(),
        };
        let bindings = Bindings {
            identifier: "test-xhd-key".into(),
            ..Default::default()
        };

        let key_id = seetle.generate_key(
            algorithm.clone(),
            false,
            Some(bindings),
            vec![KeyUsage::Sign, KeyUsage::Verify],
        ).await.unwrap();

        match key_id {
            KeyOrIdentifier::Identifier(id) => {
                assert_eq!(id, "test-xhd-key");

                // 2. Sign some data
                let data = b"hello xhd world".to_vec();
                let signature = seetle.sign(algorithm.clone(), KeyOrIdentifier::Identifier(id.clone()), data.clone()).await.unwrap();
                assert_eq!(signature.len(), 64);

                // 3. Verify the signature
                let verified = seetle.verify(algorithm, KeyOrIdentifier::Identifier(id), signature, data).await.unwrap();
                assert!(verified);
            }
            _ => panic!("Expected identifier"),
        }
    }

    #[tokio::test]
    async fn test_xhd_backend_v2_scheme() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle = backend.seetle();

        let algorithm = Algorithm::Generic {
            name: "XHD:Identity:1:5:V2".into(),
        };
        let bindings = Bindings {
            identifier: "test-xhd-v2".into(),
            ..Default::default()
        };

        let key_id = seetle.generate_key(
            algorithm.clone(),
            false,
            Some(bindings),
            vec![KeyUsage::Sign, KeyUsage::Verify],
        ).await.unwrap();

        if let KeyOrIdentifier::Identifier(id) = key_id {
            let data = b"another message".to_vec();
            let signature = seetle.sign(algorithm.clone(), KeyOrIdentifier::Identifier(id.clone()), data.clone()).await.unwrap();
            let verified = seetle.verify(algorithm, KeyOrIdentifier::Identifier(id), signature, data).await.unwrap();
            assert!(verified);
        } else {
            panic!("Expected identifier");
        }
    }

    #[tokio::test]
    async fn test_xhd_with_tpm_storage() {
        // Compose TpmStorage (mocked since no TPM) with XHDBackend
        let base_storage = Arc::new(MemoryStorage::new());
        let secure_storage = Arc::new(TpmStorage::new(base_storage).unwrap());
        
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(secure_storage, root_key);
        let seetle = backend.seetle();

        let algorithm = Algorithm::Ed25519 {
            name: "XHD:Address:0:0:Peikert".into(),
        };
        let bindings = Bindings {
            identifier: "secure-xhd-key".into(),
            ..Default::default()
        };

        // Key generation (metadata will be "wrapped" by TpmStorage)
        let key_id = seetle.generate_key(
            algorithm.clone(),
            false,
            Some(bindings),
            vec![KeyUsage::Sign],
        ).await.unwrap();

        if let KeyOrIdentifier::Identifier(id) = key_id {
            assert_eq!(id, "secure-xhd-key");
            
            // Signing (metadata will be "unwrapped" by TpmStorage)
            let data = b"secure message".to_vec();
            let signature = seetle.sign(algorithm, KeyOrIdentifier::Identifier(id), data).await.unwrap();
            assert_eq!(signature.len(), 64);
        } else {
            panic!("Expected identifier");
        }
    }
}
