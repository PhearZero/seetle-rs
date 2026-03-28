use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Seetle, SecureStorage};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use tropic01::{Tropic01, EccCurve, StartupReq};
use embedded_hal::spi::{SpiDevice, Operation, ErrorType as SpiErrorType};
use dummy_pin::DummyPin;
use std::convert::Infallible;

struct MockSpi;
impl SpiErrorType for MockSpi {
    type Error = Infallible;
}

impl SpiDevice for MockSpi {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        for op in operations {
            if let Operation::TransferInPlace(buf) = op {
                // Return dummy "Ready" status for Tropic01
                if !buf.is_empty() {
                    buf[0] = 0x01; 
                }
            }
        }
        Ok(())
    }
}

pub struct TropicBackend {
    storage: Arc<dyn SecureStorage>,
    driver: Mutex<Tropic01<MockSpi, DummyPin>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct TropicMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
    slot: u16,
}

impl TropicBackend {
    pub async fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, SeetleError> {
        let spi = MockSpi;
        let mut driver = Tropic01::new(spi);
        
        // In a real environment, we'd use a real SpiDevice and maybe startup the chip
        // For this backend, we're using a MockSpi that just allows initialization.
        let _ = driver.startup_req(StartupReq::Reboot);

        Ok(Self {
            storage,
            driver: Mutex::new(driver),
        })
    }

    async fn get_metadata(&self, identifier: &str) -> Result<TropicMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|e| SeetleError::OperationError(e.to_string()))
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
        if let Some(mut b) = bindings {
            b.extractable = extractable;
            let curve = match &algorithm {
                Algorithm::Ecdsa { named_curve, .. } if named_curve == "P-256" => EccCurve::P256,
                Algorithm::Ed25519 { .. } => EccCurve::Ed25519,
                _ => return Err(SeetleError::NotSupported),
            };

            let slot = 0; // FIXME: Slot management

            {
                let mut driver = self.driver.lock().await;
                // Use the tropic01 driver to generate a key in the given slot
                driver.ecc_key_generate(zerocopy::big_endian::U16::from(slot), curve)
                    .map_err(|e| SeetleError::OperationError(format!("Tropic01 generate failed: {:?}", e)))?;
            }

            let metadata = TropicMetadata {
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

    async fn list_keys(&self) -> Result<Vec<String>, SeetleError> {
        let keys = self.storage.list_items().await?;
        Ok(keys.into_iter().filter(|k| !k.starts_with('.')).collect())
    }

    async fn get_key_metadata(&self, identifier: String) -> Result<crate::KeyMetadata, SeetleError> {
        let metadata = self.get_metadata(&identifier).await?;
        
        Ok(crate::KeyMetadata {
            identifier,
            algorithm: format!("{:?}", metadata.algorithm),
            usages: metadata.usages,
            hardware_bound: metadata.bindings.hardware_bound,
            extractable: metadata.bindings.extractable,
            source_key_identifier: None,
            ..Default::default()
        })
    }

    async fn sign(&self, _algorithm: Algorithm, key: KeyOrIdentifier, data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        let id = match key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        let metadata = self.get_metadata(&id).await?;
        
        let signature = {
            let mut driver = self.driver.lock().await;
            
            match metadata.algorithm {
                Algorithm::Ecdsa { .. } => {
                    let hash: [u8; 32] = data.try_into().map_err(|_| SeetleError::OperationError("Data must be 32 bytes hash for ECDSA".into()))?;
                    let sig = driver.ecdsa_sign(zerocopy::big_endian::U16::from(metadata.slot), &hash)
                        .map_err(|e| SeetleError::OperationError(format!("Tropic01 sign failed: {:?}", e)))?;
                    sig.to_vec()
                }
                Algorithm::Ed25519 { .. } => {
                    let sig = driver.eddsa_sign(zerocopy::big_endian::U16::from(metadata.slot), &data)
                        .map_err(|e| SeetleError::OperationError(format!("Tropic01 sign failed: {:?}", e)))?;
                    sig.to_vec()
                }
                _ => return Err(SeetleError::NotSupported),
            }
        };
        Ok(signature)
    }

    async fn verify(&self, _algorithm: Algorithm, key: KeyOrIdentifier, signature: Vec<u8>, data: Vec<u8>) -> Result<bool, SeetleError> {
        let id = match key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        let metadata = self.get_metadata(&id).await?;

        let pubkey = {
            let mut driver = self.driver.lock().await;
            let res = driver.ecc_key_read(zerocopy::big_endian::U16::from(metadata.slot))
                .map_err(|e| SeetleError::OperationError(format!("Tropic01 read failed: {:?}", e)))?;
            res.pub_key().to_vec()
        };

        // Use ring for verification
        use ring::signature;
        match metadata.algorithm {
            Algorithm::Ecdsa { named_curve, .. } if named_curve == "P-256" => {
                let peer_public_key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, pubkey);
                Ok(peer_public_key.verify(&data, &signature).is_ok())
            }
            Algorithm::Ed25519 { .. } => {
                let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, pubkey);
                Ok(peer_public_key.verify(&data, &signature).is_ok())
            }
            _ => Err(SeetleError::NotSupported),
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

    async fn export_key(&self, _format: String, key: KeyOrIdentifier) -> Result<Vec<u8>, SeetleError> {
        let id = match key {
            KeyOrIdentifier::Identifier(id) => id,
            KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
        };

        let metadata = self.get_metadata(&id).await?;
        if !metadata.bindings.extractable {
            return Err(SeetleError::OperationError("Key is not extractable".into()));
        }

        // TROPIC01 usually doesn't allow exporting private keys from secure slots
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

