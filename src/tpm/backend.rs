use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Seetle, SecureStorage, KeyMetadata};
#[cfg(feature = "tpm")]
use crate::HardwareBound;
use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use ring::signature;

#[cfg(feature = "tpm")]
use std::sync::Mutex;
#[cfg(feature = "tpm")]
use tss_esapi::{
    Context,
    interface_types::{
        algorithm::{PublicAlgorithm, HashingAlgorithm, EccSchemeAlgorithm},
        resource_handles::Hierarchy,
        session_handles::AuthSession,
        ecc::EccCurve,
    },
    structures::{
        PublicBuilder,
        MaxBuffer,
        Digest,
        PublicKeyedHashParameters,
        KeyedHashScheme,
        PublicEccParameters,
        EccScheme,
        EccPoint,
        Public,
        KeyDerivationFunctionScheme,
        SymmetricDefinitionObject,
        SignatureScheme,
        HashScheme,
    },
    attributes::ObjectAttributesBuilder,
    traits::{Marshall, UnMarshall},
};

/// A backend that uses a TPM 2.0 (via tss-esapi) for hardware-backed keys.
pub struct TpmBackend {
    storage: Arc<dyn SecureStorage>,
    #[cfg(feature = "tpm")]
    context: Arc<Mutex<Context>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct TpmMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
    /// The wrapped private key blob from TPM.
    key_blob: Vec<u8>,
    /// The public part of the key.
    public_blob: Vec<u8>,
    /// Whether this key is derived from a hardware hierarchy.
    #[serde(default)]
    is_hierarchy_derived: bool,
}

impl TpmBackend {
    #[cfg(feature = "tpm")]
    pub fn create_context(tcti_name_conf: Option<&str>) -> Result<Arc<Mutex<Context>>, SeetleError> {
        use std::str::FromStr;
        use tss_esapi::TctiNameConf;

        // 1. If explicit TCTI provided, use only that.
        if let Some(conf) = tcti_name_conf {
            let tcti = TctiNameConf::from_str(conf).map_err(|e| SeetleError::OperationError(format!("Invalid TCTI string '{}': {}", conf, e)))?;
            let context = Context::new(tcti).map_err(|e| SeetleError::OperationError(format!("Failed to initialize TPM context with TCTI '{}': {}", conf, e)))?;
            return Ok(Arc::new(Mutex::new(context)));
        }

        // 2. Try environment variable
        if let Ok(tcti) = TctiNameConf::from_environment_variable() {
            if let Ok(context) = Context::new(tcti) {
                return Ok(Arc::new(Mutex::new(context)));
            }
        }

        // 3. Try direct device access through the Kernel Resource Manager node (/dev/tpmrm0)
        if let Ok(tcti) = TctiNameConf::from_str("device:/dev/tpmrm0") {
            if let Ok(context) = Context::new(tcti) {
                return Ok(Arc::new(Mutex::new(context)));
            }
        }

        // 4. Try tabrmd (Access Broker & Resource Manager daemon)
        if let Ok(tcti) = TctiNameConf::from_str("tabrmd:") {
            if let Ok(context) = Context::new(tcti) {
                return Ok(Arc::new(Mutex::new(context)));
            }
        }

        Err(SeetleError::OperationError(
            "Failed to initialize TPM context. Tried environment variable, tabrmd, and direct device access (/dev/tpmrm0). \
             Please ensure: \
             1. 'tpm2-abrmd' is installed and running, OR \
             2. You have read/write access to /dev/tpmrm0 (e.g., 'sudo usermod -aG tss $USER' and log out/in), OR \
             3. You pass a specific device via --tpm-device."
             .to_string()
        ))
    }

    #[cfg(feature = "tpm")]
    pub fn new(storage: Arc<dyn SecureStorage>, context: Arc<Mutex<Context>>) -> Result<Self, SeetleError> {
        Ok(Self {
            storage,
            context,
        })
    }

    #[cfg(not(feature = "tpm"))]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Result<Self, SeetleError> {
        Ok(Self {
            storage,
        })
    }

    #[cfg(feature = "tpm")]
    fn derive_deterministic_hierarchy_bits(&self, context: &mut Context, identifier: &str, requested_len: usize) -> Result<Vec<u8>, SeetleError> {
        context.set_sessions((Some(AuthSession::Password), None, None));

        let key_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|e| SeetleError::OperationError(format!("TPM error: {}", e)))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(key_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::HMAC_SHA_256))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(|e| SeetleError::OperationError(format!("TPM error: {}", e)))?;

        let primary_key_handle = context
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .map_err(|e| SeetleError::OperationError(format!("TPM create_primary error: {}", e)))?
            .key_handle;

        // Concatenate HMACs if more than 256 bits requested
        let mut accumulated = Vec::new();
        let mut counter = 1u8;
        while accumulated.len() < requested_len {
            let label = format!("{}-part-{}", identifier, counter);
            let salt = MaxBuffer::try_from(label.into_bytes())
                .map_err(|_| SeetleError::OperationError("Failed to create salt buffer".into()))?;

            let hmac_result = context
                .hmac(primary_key_handle.into(), salt, HashingAlgorithm::Sha256)
                .map_err(|e| SeetleError::OperationError(format!("TPM hmac error: {}", e)))?;
            
            accumulated.extend_from_slice(&hmac_result.to_vec());
            counter += 1;
            
            if counter > 10 { // Safeguard
                return Err(SeetleError::OperationError("Too much data requested from TPM hierarchy".into()));
            }
        }

        let _ = context.flush_context(primary_key_handle.into());
        context.set_sessions((None, None, None));

        accumulated.truncate(requested_len);
        Ok(accumulated)
    }

    #[cfg(feature = "tpm")]
    fn get_storage_parent(&self, context: &mut Context) -> Result<tss_esapi::handles::KeyHandle, SeetleError> {
        let parent_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true)
            .with_decrypt(true)
            .build()
            .map_err(|e| SeetleError::OperationError(format!("TPM parent attributes error: {}", e)))?;

        let parent_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(parent_attributes)
            .with_ecc_parameters(PublicEccParameters::new(
                SymmetricDefinitionObject::AES_256_CFB,
                EccScheme::Null,
                EccCurve::NistP256,
                KeyDerivationFunctionScheme::Null,
            ))
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| SeetleError::OperationError(format!("TPM parent public error: {}", e)))?;

        context.set_sessions((Some(AuthSession::Password), None, None));
        let parent_handle = context
            .create_primary(Hierarchy::Owner, parent_public, None, None, None, None)
            .map_err(|e| SeetleError::OperationError(format!("TPM create_primary error: {}", e)))?
            .key_handle;

        context.set_sessions((None, None, None));
        Ok(parent_handle)
    }

    async fn get_metadata(&self, identifier: &str) -> Result<TpmMetadata, SeetleError> {
        let data = self.storage.get_item(identifier).await?
            .ok_or(SeetleError::KeyNotFound)?;
        serde_json::from_slice(&data).map_err(|e| SeetleError::OperationError(e.to_string()))
    }
}


#[async_trait]
impl Seetle for TpmBackend {
    async fn generate_key(
        &self,
        _algorithm: Algorithm,
        _extractable: bool,
        _bindings: Option<Bindings>,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        #[cfg(not(feature = "tpm"))]
        {
            return Err(SeetleError::NotSupported);
        }

        #[cfg(feature = "tpm")]
        {
            let algorithm = _algorithm;
            let extractable = _extractable;
            let bindings = _bindings;
            if let Some(mut b) = bindings {
                b.extractable = extractable;
                // In a real TPM implementation, we would:
                // 1. Create/Retrieve a Primary Key in the Storage Hierarchy.
                // 2. Use `create_key` to generate a child key (ECC or RSA).
                // 3. Store the resulting `private` (wrapped) and `public` blobs in our metadata.
                
                // For now, this is a skeleton implementation showing the intent.
                // tss-esapi requires a lot of boilerplate for full key creation.
                
                match algorithm {
                    Algorithm::Generic { .. } | Algorithm::Raw { .. } => {
                        let requested_len = if let Algorithm::Raw { length } = algorithm {
                            (length / 8) as usize
                        } else {
                            32 // Default to 256 bits for generic seeds
                        };

                        let (bits, is_hierarchy_derived) = if b.hardware_bound == HardwareBound::Yes {
                            // Deterministic hierarchy-based derivation for hardware-bound seeds
                            let mut context = self.context.lock().unwrap();
                            let derived_bits = self.derive_deterministic_hierarchy_bits(&mut context, &b.identifier, requested_len)?;
                            (derived_bits, true)
                        } else {
                            let bits = {
                                let mut context = self.context.lock().unwrap();
                                let mut accumulated = Vec::new();
                                while accumulated.len() < requested_len {
                                    let to_get = requested_len - accumulated.len();
                                    let next_batch = context.get_random(std::cmp::min(to_get, 64))
                                        .map_err(|e| SeetleError::OperationError(format!("TPM get_random error: {}", e)))?;
                                    accumulated.extend_from_slice(&next_batch);
                                }
                                accumulated
                            };
                            (bits, false)
                        };

                        let metadata = TpmMetadata {
                            bindings: b.clone(),
                            algorithm: algorithm.clone(),
                            usages: _key_usages,
                            public_blob: Vec::new(),
                            key_blob: if is_hierarchy_derived { Vec::new() } else { bits },
                            is_hierarchy_derived,
                        };
                        let data = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
                        self.storage.set_item(&b.identifier, data).await?;
                        return Ok(KeyOrIdentifier::Identifier(b.identifier));
                    }
                    Algorithm::Ecdsa { ref named_curve, .. } if named_curve == "P-256" => {
                let (public_blob, key_blob) = {
                    let mut context = self.context.lock().unwrap();
                    let parent_handle = self.get_storage_parent(&mut context)?;
                    
                    let key_attributes = ObjectAttributesBuilder::new()
                        .with_fixed_tpm(true)
                        .with_fixed_parent(true)
                        .with_sensitive_data_origin(true)
                        .with_user_with_auth(true)
                        .with_sign_encrypt(true)
                        .build()
                        .map_err(|e| SeetleError::OperationError(format!("TPM key attributes error: {}", e)))?;

                    let public = PublicBuilder::new()
                        .with_public_algorithm(PublicAlgorithm::Ecc)
                        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                        .with_object_attributes(key_attributes)
                        .with_ecc_parameters(PublicEccParameters::new(
                            SymmetricDefinitionObject::Null,
                            EccScheme::create(EccSchemeAlgorithm::EcDsa, Some(HashingAlgorithm::Sha256), None).map_err(|e| SeetleError::OperationError(format!("TPM scheme error: {}", e)))?,
                            EccCurve::NistP256,
                            KeyDerivationFunctionScheme::Null,
                        ))
                        .with_ecc_unique_identifier(EccPoint::default())
                        .build()
                        .map_err(|e| SeetleError::OperationError(format!("TPM key public error: {}", e)))?;

                    context.set_sessions((Some(AuthSession::Password), None, None));
                    let result = context
                        .create(parent_handle, public, None, None, None, None)
                        .map_err(|e| SeetleError::OperationError(format!("TPM create error: {}", e)))?;

                    let _ = context.flush_context(parent_handle.into());
                    context.set_sessions((None, None, None));
                    
                    (
                        result.out_public.marshall().map_err(|e| SeetleError::OperationError(format!("TPM marshalling error: {}", e)))?,
                        result.out_private.to_vec()
                    )
                };

                let metadata = TpmMetadata {
                    bindings: b.clone(),
                    algorithm: algorithm.clone(),
                    usages: _key_usages.clone(),
                    public_blob,
                    key_blob,
                    is_hierarchy_derived: false,
                };
                        
                        let data = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
                        self.storage.set_item(&b.identifier, data).await?;
                        return Ok(KeyOrIdentifier::Identifier(b.identifier));
                    }
                    Algorithm::Ed25519 { .. } => {
                        // Ed25519 logic here
                    }
                    Algorithm::RsaPss { modulus_length, .. } if modulus_length >= 2048 => {
                        // RSA-PSS logic here
                    }
                    _ => return Err(SeetleError::NotSupported),
                }

                return Err(SeetleError::OperationError("TPM key generation for this algorithm not fully implemented in this skeleton".into()));
            }

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
            return Err(SeetleError::AccessDenied);
        }
        metadata.bindings = new_bindings;
        let data = serde_json::to_vec(&metadata).map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, data).await?;
        Ok(())
    }

    async fn delete_key(
        &self,
        identifier: String,
    ) -> Result<(), SeetleError> {
        self.storage.remove_item(&identifier).await
    }

    async fn list_keys(&self) -> Result<Vec<String>, SeetleError> {
        let keys = self.storage.list_items().await?;
        Ok(keys.into_iter().filter(|k| !k.starts_with('.')).collect())
    }

    async fn get_key_metadata(&self, identifier: String) -> Result<KeyMetadata, SeetleError> {
        let metadata = self.get_metadata(&identifier).await?;
        
        #[allow(unused_mut)]
        let mut public_key = None;
        if !metadata.public_blob.is_empty() {
            #[cfg(feature = "tpm")]
            {
                if let Ok(public) = Public::unmarshall(&metadata.public_blob) {
                    match public {
                        Public::Ecc { parameters, unique, .. } => {
                            if parameters.ecc_curve() == EccCurve::NistP256 {
                                let mut raw_pub = vec![0x04]; // Uncompressed prefix
                                raw_pub.extend_from_slice(unique.x().value());
                                raw_pub.extend_from_slice(unique.y().value());
                                public_key = Some(raw_pub);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(KeyMetadata {
            identifier,
            algorithm: format!("{:?}", metadata.algorithm),
            usages: metadata.usages,
            hardware_bound: metadata.bindings.hardware_bound,
            extractable: metadata.bindings.extractable,
            public_key,
            source_key_identifier: None,
            ..Default::default()
        })
    }

    async fn sign(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        #[cfg(not(feature = "tpm"))]
        {
            let _ = data;
            return Err(SeetleError::NotSupported);
        }

        #[cfg(feature = "tpm")]
        {
            let key = _key;
            let identifier = match key {
                KeyOrIdentifier::Identifier(id) => id,
                KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
            };

            let metadata = self.get_metadata(&identifier).await?;
            
            if metadata.is_hierarchy_derived {
                return Err(SeetleError::OperationError("Hierarchy-derived seeds do not support direct signing. Use them for derivation.".into()));
            }

            let mut signature_vec = Vec::new();
            {
                let mut context = self.context.lock().unwrap();
                let parent_handle = self.get_storage_parent(&mut context)?;
                
                let key_handle = {
                    context.set_sessions((Some(AuthSession::Password), None, None));
                    let res = context
                        .load(
                            parent_handle,
                            metadata.key_blob.try_into().map_err(|_| SeetleError::DataError)?,
                            Public::unmarshall(&metadata.public_blob).map_err(|_| SeetleError::DataError)?,
                        )
                        .map_err(|e| SeetleError::OperationError(format!("TPM load error: {}", e)))?;
                    context.set_sessions((None, None, None));
                    res
                };

                context.set_sessions((None, None, None));
                let (digest, validation) = context
                    .hash(
                        MaxBuffer::try_from(data).map_err(|_| SeetleError::OperationError("Data too large for TPM hashing".into()))?,
                        HashingAlgorithm::Sha256,
                        Hierarchy::Null,
                    )
                    .map_err(|e| SeetleError::OperationError(format!("TPM hash error: {}", e)))?;

                context.set_sessions((Some(AuthSession::Password), None, None));
                let signature = context
                    .sign(
                        key_handle,
                        digest,
                        SignatureScheme::EcDsa { hash_scheme: HashScheme::new(HashingAlgorithm::Sha256) },
                        validation,
                    )
                    .map_err(|e| SeetleError::OperationError(format!("TPM sign error: {}", e)))?;
                context.set_sessions((None, None, None));

                let _ = context.flush_context(key_handle.into());
                let _ = context.flush_context(parent_handle.into());

                match signature {
                    tss_esapi::structures::Signature::EcDsa(signature_data) => {
                        signature_vec.extend_from_slice(signature_data.signature_r().value());
                        signature_vec.extend_from_slice(signature_data.signature_s().value());
                    }
                    _ => return Err(SeetleError::OperationError("Unexpected signature format from TPM".into())),
                }
            }
            Ok(signature_vec)
        }
    }

    async fn verify(
        &self,
        _algorithm: Algorithm,
        key: KeyOrIdentifier,
        signature: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<bool, SeetleError> {
        let identifier = match key {
            KeyOrIdentifier::Identifier(id) => id,
            KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
        };

        let metadata = self.get_key_metadata(identifier).await?;
        let public_key = metadata.public_key.ok_or(SeetleError::OperationError("Public key not found for verification".into()))?;

        match &metadata.algorithm {
            alg if alg.contains("Ecdsa") && alg.contains("P-256") => {
                let peer_public_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_FIXED,
                    public_key,
                );
                Ok(peer_public_key.verify(&data, &signature).is_ok())
            }
            _ => Err(SeetleError::NotSupported),
        }
    }

    async fn encrypt(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn decrypt(
        &self,
        _algorithm: Algorithm,
        _key: KeyOrIdentifier,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn digest(
        &self,
        _algorithm: Algorithm,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn wrap_key(
        &self,
        _format: String,
        _key: CryptoKey,
        _wrapping_key: KeyOrIdentifier,
        _wrap_algorithm: Algorithm,
    ) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn unwrap_key(
        &self,
        _format: String,
        _wrapped_key: Vec<u8>,
        _unwrapping_key: KeyOrIdentifier,
        _unwrap_algorithm: Algorithm,
        _unwrapped_key_algorithm: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_key(
        &self,
        _algorithm: Algorithm,
        _base_key: KeyOrIdentifier,
        _derived_key_type: Algorithm,
        _extractable: bool,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_bits(
        &self,
        _algorithm: Algorithm,
        _base_key: KeyOrIdentifier,
        _length: u32,
    ) -> Result<Vec<u8>, SeetleError> {
        #[cfg(not(feature = "tpm"))]
        {
            return Err(SeetleError::NotSupported);
        }

        #[cfg(feature = "tpm")]
        {
            let length = _length;
            let base_key = _base_key;
            let identifier = match base_key {
                KeyOrIdentifier::Identifier(id) => id,
                KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
            };

            // 1. Try to load from storage for persistence
            let (material, is_hierarchy_derived) = if let Ok(Some(data)) = self.storage.get_item(&identifier).await {
                // Check if it's metadata (JSON)
                if let Ok(metadata) = serde_json::from_slice::<TpmMetadata>(&data) {
                    (metadata.key_blob, metadata.is_hierarchy_derived)
                } else {
                    // Fallback to raw bits (backward compatibility)
                    (data, false)
                }
            } else {
                return Err(SeetleError::KeyNotFound);
            };

            let result_material = if is_hierarchy_derived {
                let mut context = self.context.lock().unwrap();
                self.derive_deterministic_hierarchy_bits(&mut context, &identifier, (length / 8) as usize)?
            } else {
                material
            };

            if result_material.len() == (length / 8) as usize {
                Ok(result_material)
            } else if length == 512 {
                // Consistent with KeyringBackend: if asking for 512 bits, use SHA-512 to derive from key material.
                use ring::digest;
                let hash = digest::digest(&digest::SHA512, &result_material);
                Ok(hash.as_ref().to_vec())
            } else {
                Err(SeetleError::OperationError(format!(
                    "Stored seed for {} has wrong length and cannot be derived: expected {}, got {}", 
                    identifier, (length / 8), result_material.len()
                )))
            }
        }
    }

    async fn export_key(
        &self,
        _format: String,
        key: KeyOrIdentifier,
    ) -> Result<Vec<u8>, SeetleError> {
        match key {
            KeyOrIdentifier::Identifier(id) => {
                let metadata = self.get_metadata(&id).await?;
                if !metadata.bindings.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                // For bits/generic, the key material is in key_blob or hierarchy-derived
                if metadata.key_blob.is_empty() {
                    #[cfg(feature = "tpm")]
                    {
                        if metadata.is_hierarchy_derived {
                            let mut context = self.context.lock().unwrap();
                            let requested_len = match metadata.algorithm {
                                Algorithm::Raw { length } => (length / 8) as usize,
                                _ => 32,
                            };
                            return self.derive_deterministic_hierarchy_bits(&mut context, &id, requested_len);
                        }
                    }
                    return Err(SeetleError::OperationError("Key material not available for export".into()));
                }
                Ok(metadata.key_blob.clone())
            }
            KeyOrIdentifier::Key(k) => {
                if !k.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                Err(SeetleError::NotSupported)
            }
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;

    #[tokio::test]
    async fn test_tpm_backend_creation() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        {
            let result = TpmBackend::new(storage);
            assert!(result.is_ok());
        }

        #[cfg(feature = "tpm")]
        {
            let context = TpmBackend::create_context(None);
            if let Ok(ctx) = context {
                let result = TpmBackend::new(storage, ctx);
                assert!(result.is_ok());
            } else {
                println!("Skipping TPM backend creation test: No TPM available");
            }
        }
    }

    #[tokio::test]
    async fn test_tpm_derive_bits() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        let backend = TpmBackend::new(storage.clone()).unwrap();

        #[cfg(feature = "tpm")]
        let backend = {
            let context = TpmBackend::create_context(None);
            match context {
                Ok(ctx) => TpmBackend::new(storage.clone(), ctx).unwrap(),
                Err(_) => return, // Skip
            }
        };

        let identifier = "test-seed-128";
        let length = 128; // 16 bytes

        #[cfg(feature = "tpm")]
        {
            // First generation
            backend.generate_key(
                Algorithm::Raw { length },
                false,
                Some(Bindings {
                    identifier: identifier.into(),
                    ..Default::default()
                }),
                vec![]
            ).await.expect("Failed to generate seed via TPM");
        }

        let bits_result = backend.derive_bits(
            Algorithm::Raw { length },
            KeyOrIdentifier::Identifier(identifier.into()),
            length
        ).await;

        #[cfg(not(feature = "tpm"))]
        {
            assert!(matches!(bits_result, Err(SeetleError::NotSupported)));
        }

        #[cfg(feature = "tpm")]
        {
            let bits = bits_result.expect("Failed to derive bits via TPM");
            assert_eq!(bits.len(), 16);

            // Verify persistence in storage (it should be stored as metadata now)
            let stored_data = storage.get_item(identifier).await.unwrap()
                .expect("Metadata should be persisted in storage");
            let metadata: TpmMetadata = serde_json::from_slice(&stored_data).unwrap();
            assert_eq!(bits, metadata.key_blob);

            // Second call should return same bits from storage
            let bits2 = backend.derive_bits(
                Algorithm::Raw { length },
                KeyOrIdentifier::Identifier(identifier.into()),
                length
            ).await.unwrap();

            assert_eq!(bits, bits2);
        }
    }

    #[tokio::test]
    async fn test_tpm_delete_key() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        
        #[cfg(not(feature = "tpm"))]
        let backend = TpmBackend::new(storage.clone()).unwrap();

        #[cfg(feature = "tpm")]
        let backend = {
            let context = TpmBackend::create_context(None);
            match context {
                Ok(ctx) => TpmBackend::new(storage.clone(), ctx).unwrap(),
                Err(_) => return, // Skip
            }
        };

        let identifier = "key-to-delete";
        storage.set_item(identifier, vec![1, 2, 3]).await.unwrap();
        
        backend.delete_key(identifier.to_string()).await.expect("Delete should succeed");
        
        let exists = storage.get_item(identifier).await.unwrap().is_some();
        assert!(!exists, "Key should be removed from storage");
    }

    #[tokio::test]
    async fn test_tpm_master_seed_persistence() {
        #[cfg(feature = "tpm")]
        {
            let storage = Arc::new(MemoryStorage::new());
            let context_res = TpmBackend::create_context(None);
            if let Ok(ctx) = context_res {
                let backend = TpmBackend::new(storage.clone(), ctx.clone()).unwrap();
                let master_id = "seetle-master-seed".to_string();

                // 1. Generate master seed
                backend.generate_key(
                    Algorithm::Generic { name: "Master".into() },
                    true,
                    Some(Bindings {
                        identifier: master_id.clone(),
                        hardware_bound: HardwareBound::Yes,
                        ..Default::default()
                    }),
                    vec![KeyUsage::DeriveBits]
                ).await.unwrap();

                // 2. Derive bits, should be deterministic
                let bits1 = backend.derive_bits(
                    Algorithm::Raw { length: 256 },
                    KeyOrIdentifier::Identifier(master_id.clone()),
                    256
                ).await.unwrap();
                
                assert_eq!(bits1.len(), 32);

                let bits2 = backend.derive_bits(
                    Algorithm::Raw { length: 256 },
                    KeyOrIdentifier::Identifier(master_id.clone()),
                    256
                ).await.unwrap();
                
                assert_eq!(bits1, bits2);
            }
        }
    }

    #[tokio::test]
    async fn test_tpm_metadata_persistence() {
        #[cfg(feature = "tpm")]
        {
            let storage = Arc::new(MemoryStorage::new());
            let context_res = TpmBackend::create_context(None);
            if let Ok(ctx) = context_res {
                let backend = TpmBackend::new(storage.clone(), ctx.clone()).unwrap();
                let master_id = "seetle-master-seed".to_string();

                // 1. Initially it should NOT be in the list
                let keys = backend.list_keys().await.unwrap();
                assert!(!keys.contains(&master_id));

                // 2. Generate it
                backend.generate_key(
                    Algorithm::Generic { name: "Master".into() },
                    true,
                    Some(Bindings {
                        identifier: master_id.clone(),
                        hardware_bound: HardwareBound::Yes,
                        ..Default::default()
                    }),
                    vec![KeyUsage::DeriveBits]
                ).await.unwrap();

                // 3. Now it should be there
                let keys2 = backend.list_keys().await.unwrap();
                assert!(keys2.contains(&master_id));

                let meta = backend.get_key_metadata(master_id.clone()).await.unwrap();
                assert_eq!(meta.identifier, master_id);
                assert_eq!(meta.hardware_bound, HardwareBound::Yes);
            }
        }
    }

    #[tokio::test]
    async fn test_tpm_ecdsa_p256() {
        #[cfg(feature = "tpm")]
        {
            let storage = Arc::new(crate::memory::storage::MemoryStorage::new());
            let context_res = TpmBackend::create_context(None);
            if let Ok(ctx) = context_res {
                let backend = TpmBackend::new(storage.clone(), ctx.clone()).unwrap();
                let id = "test-ecdsa-p256";
                let algorithm = Algorithm::Ecdsa { 
                    name: "ECDSA".to_string(),
                    named_curve: "P-256".to_string(),
                    hash: Some("SHA-256".to_string()),
                };

                // 1. Generate key
                backend.generate_key(
                    algorithm.clone(),
                    false,
                    Some(Bindings {
                        identifier: id.to_string(),
                        ..Default::default()
                    }),
                    vec![KeyUsage::Sign, KeyUsage::Verify]
                ).await.unwrap();

                // 2. Sign some data
                let data = b"hello world".to_vec();
                let signature = backend.sign(
                    algorithm.clone(),
                    KeyOrIdentifier::Identifier(id.to_string()),
                    data.clone()
                ).await.unwrap();

                assert!(!signature.is_empty());
                
                // 3. Verify
                let is_valid = backend.verify(
                    algorithm.clone(),
                    KeyOrIdentifier::Identifier(id.to_string()),
                    signature,
                    data
                ).await.unwrap();

                assert!(is_valid);
            }
        }
    }
}
