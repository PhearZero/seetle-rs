use crate::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, SeetleError, CryptoKey, Seetle, SecureStorage, KeyMetadata, HardwareBound};
use async_trait::async_trait;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use xhd_wallet_api::{XPrv, DerivationScheme, KeyContext, key_gen, Signature};
use std::str::FromStr;
use ring::aead::{self, Aad, UnboundKey};
use ring::rand::{SystemRandom, SecureRandom};
use rand;
use rand::rngs::OsRng;
use curve25519_dalek::edwards::CompressedEdwardsY;
use x25519_dalek::{StaticSecret, PublicKey};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    OpModeR, OpModeS,
    Serializable, Deserializable,
};

/// A source for the xHD root key.
pub enum RootKeySource {
    /// A direct XPrv in memory.
    Direct(XPrv),
    /// A root key derived from another backend.
    Backend {
        /// The backend that will provide the root key material.
        backend: Arc<dyn Seetle>,
        /// The identifier for the master key in the backend.
        identifier: String,
        /// The algorithm to use for derivation or export.
        algorithm: Algorithm,
    },
}

/// A backend that uses xHD-Wallet-API for hierarchical deterministic Ed25519 keys.
pub struct XHDBackend {
    storage: Arc<dyn SecureStorage>,
    root_key_source: RootKeySource,
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


#[derive(Serialize, Deserialize, Clone)]
struct StandaloneMetadata {
    bindings: Bindings,
    algorithm: Algorithm,
    usages: Vec<KeyUsage>,
    seed: Vec<u8>,
    source_key_identifier: Option<String>,
    #[serde(default)]
    context: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum XHDStorageItem {
    Key(XHDMetadata),
    Standalone(StandaloneMetadata),
}

impl XHDBackend {
    pub fn new(storage: Arc<dyn SecureStorage>, root_key: XPrv) -> Self {
        Self {
            storage,
            root_key_source: RootKeySource::Direct(root_key),
        }
    }

    /// Creates a new XHDBackend that uses another Seetle backend for its root key.
    pub fn new_with_backend(
        storage: Arc<dyn SecureStorage>,
        root_backend: Arc<dyn Seetle>,
        root_identifier: String,
        root_algorithm: Algorithm,
    ) -> Self {
        Self {
            storage,
            root_key_source: RootKeySource::Backend {
                backend: root_backend,
                identifier: root_identifier,
                algorithm: root_algorithm,
            },
        }
    }

    async fn get_root_key(&self) -> Result<XPrv, SeetleError> {
        match &self.root_key_source {
            RootKeySource::Direct(key) => Ok(key.clone()),
            RootKeySource::Backend { backend, identifier, algorithm } => {
                // Try derive_bits first (to get a seed)
                match backend.derive_bits(algorithm.clone(), KeyOrIdentifier::Identifier(identifier.clone()), 512).await {
                    Ok(seed) => {
                        if seed.len() == 64 {
                            let mut seed_arr = [0u8; 64];
                            seed_arr.copy_from_slice(&seed);
                            Ok(XPrv::from_seed(&seed_arr))
                        } else {
                            Err(SeetleError::OperationError("Invalid seed length from backend".into()))
                        }
                    }
                    Err(_) => {
                        // Fallback to export_key if derive_bits is not supported
                        // This requires the key to be extractable in the backend
                        let crypto_key = CryptoKey {
                            key_type: crate::KeyType::Private,
                            extractable: true,
                            algorithm: algorithm.clone(),
                            usages: vec![],
                        };
                        let key_data = backend.export_key("raw".into(), KeyOrIdentifier::Key(crypto_key)).await?;
                        // We assume the exported key data is valid for XPrv (this is backend-dependent)
                        // For simplicity, we try to treat it as a seed if it's 64 bytes
                        if key_data.len() == 64 {
                            let mut seed_arr = [0u8; 64];
                            seed_arr.copy_from_slice(&key_data);
                            Ok(XPrv::from_seed(&seed_arr))
                        } else {
                            Err(SeetleError::OperationError("Exported key not suitable for XHD root".into()))
                        }
                    }
                }
            }
        }
    }

    fn get_root_backend_if_matches(&self, identifier: &str) -> Option<Arc<dyn Seetle>> {
        if let RootKeySource::Backend { backend, identifier: root_id, .. } = &self.root_key_source {
            if identifier == root_id {
                return Some(backend.clone());
            }
        }
        None
    }

    async fn determine_hardware_bound(&self, local_status: HardwareBound) -> HardwareBound {
        if let RootKeySource::Backend { backend, identifier: root_id, .. } = &self.root_key_source {
            if let Ok(root_meta) = backend.get_key_metadata(root_id.clone()).await {
                if root_meta.hardware_bound == HardwareBound::Yes || root_meta.hardware_bound == HardwareBound::Partial {
                    return HardwareBound::Partial;
                }
            }
        }
        local_status
    }

    async fn get_metadata(&self, identifier: &str) -> Result<XHDStorageItem, SeetleError> {
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

        if let Some(mut b) = bindings {
            b.extractable = extractable;
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
        let item = self.get_metadata(&identifier).await?;
        let mut metadata = match item {
            XHDStorageItem::Key(m) => m,
            _ => return Err(SeetleError::OperationError("Only keys can be updated".into())),
        };
        if !metadata.bindings.updatable {
            return Err(SeetleError::OperationError("Key is not updatable".into()));
        }
        metadata.bindings = new_bindings;
        let metadata_bytes = serde_json::to_vec(&XHDStorageItem::Key(metadata)).map_err(|e| SeetleError::OperationError(e.to_string()))?;
        self.storage.set_item(&identifier, metadata_bytes).await?;
        Ok(())
    }

    async fn delete_key(&self, identifier: String) -> Result<(), SeetleError> {
        self.storage.remove_item(&identifier).await?;
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<String>, SeetleError> {
        let mut keys = self.storage.list_items().await?;
        if let RootKeySource::Backend { identifier, .. } = &self.root_key_source {
            if !keys.contains(identifier) {
                keys.push(identifier.clone());
            }
        }
        // Filter out hidden internal keys
        Ok(keys.into_iter().filter(|k| !k.starts_with('.')).collect())
    }

    async fn get_key_metadata(&self, identifier: String) -> Result<KeyMetadata, SeetleError> {
        // Delegate to root backend if identifier matches
        if let RootKeySource::Backend { backend, identifier: root_id, .. } = &self.root_key_source {
            if identifier == *root_id {
                let mut metadata = backend.get_key_metadata(identifier).await?;
                metadata.hardware_bound = self.determine_hardware_bound(metadata.hardware_bound).await;
                return Ok(metadata);
            }
        }

        let item = self.get_metadata(&identifier).await?;
        match item {
            XHDStorageItem::Key(metadata) => {
                let context_enum = match metadata.context.as_str() {
                    "Address" => KeyContext::Address,
                    "Identity" => KeyContext::Identity,
                    _ => return Err(SeetleError::DataError),
                };
                let scheme_enum = match metadata.scheme.as_str() {
                    "Peikert" => DerivationScheme::Peikert,
                    "V2" => DerivationScheme::V2,
                    _ => return Err(SeetleError::DataError),
                };

                let root_key = self.get_root_key().await?;
                let derived_xprv = key_gen(&root_key, context_enum, metadata.account, metadata.key_index, scheme_enum)
                    .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;
                let public_key = derived_xprv.public().public_key().to_vec();

                let hardware_bound = self.determine_hardware_bound(metadata.bindings.hardware_bound).await;

                Ok(KeyMetadata {
                    identifier,
                    algorithm: format!("{:?}", metadata.algorithm),
                    usages: metadata.usages,
                    hardware_bound,
                    extractable: metadata.bindings.extractable,
                    public_key: Some(public_key),
                    context: Some(metadata.context),
                    account: Some(metadata.account),
                    index: Some(metadata.key_index),
                    derivation: Some(metadata.scheme),
                    source_key_identifier: None,
                })
            }
            XHDStorageItem::Standalone(metadata) => {
                let mut public_key = None;
                let context = if let Some(ctx) = &metadata.context {
                    ctx.clone()
                } else if metadata.source_key_identifier.is_some() {
                    "ECDH".to_string()
                } else {
                    "Standalone".to_string()
                };
                let algorithm = format!("{:?}", metadata.algorithm);

                match &metadata.algorithm {
                    _ => {
                        if metadata.seed.len() == 64 {
                            let mut seed = [0u8; 64];
                            seed.copy_from_slice(&metadata.seed);
                            let xprv = XPrv::from_seed(&seed);
                            public_key = Some(xprv.public().public_key().to_vec());
                        }
                    }
                }

                Ok(KeyMetadata {
                    identifier,
                    algorithm,
                    usages: metadata.usages,
                    hardware_bound: self.determine_hardware_bound(metadata.bindings.hardware_bound).await,
                    extractable: metadata.bindings.extractable,
                    public_key,
                    context: Some(context),
                    account: None,
                    index: None,
                    derivation: None,
                    source_key_identifier: metadata.source_key_identifier,
                })
            }
        }
    }

    async fn sign(&self, algorithm: Algorithm, key: KeyOrIdentifier, data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        let id = match &key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        if let Some(backend) = self.get_root_backend_if_matches(id) {
            return backend.sign(algorithm, key, data).await;
        }

        let item = self.get_metadata(id).await?;
        match item {
            XHDStorageItem::Key(metadata) => {
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

                let root_key = self.get_root_key().await?;
                let derived_xprv = key_gen(&root_key, context, metadata.account, metadata.key_index, scheme)
                    .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;

                let signature: Signature<Vec<u8>> = derived_xprv.sign(&data);
                Ok(signature.to_bytes().to_vec())
            }
            XHDStorageItem::Standalone(metadata) => {
                if metadata.seed.len() != 64 {
                    return Err(SeetleError::OperationError("Invalid standalone key seed".into()));
                }
                let mut seed = [0u8; 64];
                seed.copy_from_slice(&metadata.seed);
                let xprv = XPrv::from_seed(&seed);
                let signature: Signature<Vec<u8>> = xprv.sign(&data);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    async fn verify(&self, algorithm: Algorithm, key: KeyOrIdentifier, signature: Vec<u8>, data: Vec<u8>) -> Result<bool, SeetleError> {
        let id = match &key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        if let Some(backend) = self.get_root_backend_if_matches(id) {
            return backend.verify(algorithm, key, signature, data).await;
        }

        let item = self.get_metadata(id).await?;
        match item {
            XHDStorageItem::Key(metadata) => {
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

                let root_key = self.get_root_key().await?;
                let derived_xprv = key_gen(&root_key, context, metadata.account, metadata.key_index, scheme)
                    .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;
                let xpub = derived_xprv.public();

                let sig = Signature::<u8>::from_slice(&signature)
                    .map_err(|_| SeetleError::DataError)?;

                Ok(xpub.verify(&data, &sig))
            }
            XHDStorageItem::Standalone(metadata) => {
                if metadata.seed.len() != 64 {
                    return Err(SeetleError::OperationError("Invalid standalone key seed".into()));
                }
                let mut seed = [0u8; 64];
                seed.copy_from_slice(&metadata.seed);
                let xprv = XPrv::from_seed(&seed);
                let xpub = xprv.public();

                let sig = Signature::<u8>::from_slice(&signature)
                    .map_err(|_| SeetleError::DataError)?;

                Ok(xpub.verify(&data, &sig))
            }
        }
    }

    async fn encrypt(&self, algorithm: Algorithm, key: KeyOrIdentifier, data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        let id = match &key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        if let Some(backend) = self.get_root_backend_if_matches(id) {
            return backend.encrypt(algorithm, key, data).await;
        }

        match algorithm {
            Algorithm::Hpke { name: _, public_key: Some(pub_key), info } => {
                // Load peer public key
                let compressed = CompressedEdwardsY::from_slice(&pub_key)
                    .map_err(|_| SeetleError::DataError)?;
                let edwards_point = compressed.decompress()
                    .ok_or(SeetleError::DataError)?;
                let montgomery_point = edwards_point.to_montgomery();
                let peer_pub_key = <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(&montgomery_point.to_bytes())
                    .map_err(|_| SeetleError::DataError)?;

                let info_bytes = info.unwrap_or_default();

                let (encapped_key, mut sender_ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                    &OpModeS::Base,
                    &peer_pub_key,
                    &info_bytes,
                    &mut OsRng,
                ).map_err(|e| SeetleError::OperationError(format!("HPKE setup sender error: {:?}", e)))?;

                let ciphertext = sender_ctx.seal(&data, &[])
                    .map_err(|e| SeetleError::OperationError(format!("HPKE seal error: {:?}", e)))?;

                // Combine encapsulated key and ciphertext
                let mut combined = encapped_key.to_bytes().to_vec();
                combined.extend_from_slice(&ciphertext);
                Ok(combined)
            }
            _ => {
                // Existing symmetric encryption
                let id = match key {
                    KeyOrIdentifier::Identifier(id) => id,
                    _ => return Err(SeetleError::NotSupported),
                };
                let item = self.get_metadata(&id).await?;
                let key_bytes = match item {
                    XHDStorageItem::Key(metadata) => {
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

                        let root_key = self.get_root_key().await?;
                        let derived_xprv = key_gen(&root_key, context, metadata.account, metadata.key_index, scheme)
                            .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;

                        let xprv_bytes = derived_xprv.extended_secret_key_bytes();
                        xprv_bytes[0..32].to_vec()
                    }
                    XHDStorageItem::Standalone(metadata) => {
                        if metadata.seed.len() != 64 {
                            return Err(SeetleError::OperationError("Invalid standalone key seed".into()));
                        }
                        let mut seed = [0u8; 64];
                        seed.copy_from_slice(&metadata.seed);
                        let xprv = XPrv::from_seed(&seed);
                        let xprv_bytes = xprv.extended_secret_key_bytes();
                        xprv_bytes[0..32].to_vec()
                    }
                };

                let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
                    .map_err(|_| SeetleError::OperationError("Failed to create ring key".into()))?;
                let encryption_key = aead::LessSafeKey::new(unbound_key);

                let rng = SystemRandom::new();
                let mut nonce_bytes = [0u8; aead::NONCE_LEN];
                rng.fill(&mut nonce_bytes).map_err(|_| SeetleError::OperationError("RNG error".into()))?;
                let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

                let mut in_out = data;
                encryption_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                    .map_err(|_| SeetleError::OperationError("Encryption failed".into()))?;

                let mut result = Vec::with_capacity(aead::NONCE_LEN + in_out.len());
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&in_out);
                Ok(result)
            }
        }
    }

    async fn decrypt(&self, algorithm: Algorithm, key: KeyOrIdentifier, data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        let id = match &key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        if let Some(backend) = self.get_root_backend_if_matches(id) {
            return backend.decrypt(algorithm, key, data).await;
        }

        match algorithm {
            Algorithm::Hpke { name: _, public_key: _, info } => {
                if data.len() < 32 {
                    return Err(SeetleError::DataError);
                }
                let (encapped_bytes, ciphertext) = data.split_at(32);

                let id = match key {
                    KeyOrIdentifier::Identifier(id) => id,
                    _ => return Err(SeetleError::NotSupported),
                };
                let item = self.get_metadata(&id).await?;
                let metadata = match item {
                    XHDStorageItem::Key(m) => m,
                    _ => return Err(SeetleError::OperationError("HPKE requires an asymmetric key".into())),
                };

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

                let root_key = self.get_root_key().await?;
                let derived_xprv = key_gen(&root_key, context, metadata.account, metadata.key_index, scheme)
                    .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;

                // Convert Ed25519 secret key to X25519
                let xprv_bytes = derived_xprv.extended_secret_key_bytes();
                let mut scalar_bytes = [0u8; 32];
                scalar_bytes.copy_from_slice(&xprv_bytes[0..32]);
                let secret = StaticSecret::from(scalar_bytes);
                let hpke_secret = <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(&secret.to_bytes())
                    .map_err(|_| SeetleError::OperationError("Failed to load HPKE secret key".into()))?;

                let encapped_key = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(encapped_bytes)
                    .map_err(|_| SeetleError::DataError)?;

                let info_bytes = info.unwrap_or_default();

                let mut receiver_ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
                    &OpModeR::Base,
                    &hpke_secret,
                    &encapped_key,
                    &info_bytes,
                ).map_err(|e| SeetleError::OperationError(format!("HPKE setup receiver error: {:?}", e)))?;

                let decrypted_data = receiver_ctx.open(ciphertext, &[])
                    .map_err(|e| SeetleError::OperationError(format!("HPKE open error: {:?}", e)))?;

                Ok(decrypted_data)
            }
            _ => {
                // Existing symmetric decryption
                if data.len() < aead::NONCE_LEN + 16 {
                    return Err(SeetleError::DataError);
                }

                let id = match key {
                    KeyOrIdentifier::Identifier(id) => id,
                    _ => return Err(SeetleError::NotSupported),
                };
                let item = self.get_metadata(&id).await?;
                let key_bytes = match item {
                    XHDStorageItem::Key(metadata) => {
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

                        let root_key = self.get_root_key().await?;
                        let derived_xprv = key_gen(&root_key, context, metadata.account, metadata.key_index, scheme)
                            .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;

                        let xprv_bytes = derived_xprv.extended_secret_key_bytes();
                        xprv_bytes[0..32].to_vec()
                    }
                    XHDStorageItem::Standalone(metadata) => {
                        if metadata.seed.len() != 64 {
                            return Err(SeetleError::OperationError("Invalid standalone key seed".into()));
                        }
                        let mut seed = [0u8; 64];
                        seed.copy_from_slice(&metadata.seed);
                        let xprv = XPrv::from_seed(&seed);
                        let xprv_bytes = xprv.extended_secret_key_bytes();
                        xprv_bytes[0..32].to_vec()
                    }
                };

                let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
                    .map_err(|_| SeetleError::OperationError("Failed to create ring key".into()))?;
                let encryption_key = aead::LessSafeKey::new(unbound_key);

                let (nonce_bytes, ciphertext) = data.split_at(aead::NONCE_LEN);
                let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
                    .map_err(|_| SeetleError::OperationError("Invalid nonce".into()))?;

                let mut in_out = ciphertext.to_vec();
                let decrypted_data = encryption_key.open_in_place(nonce, Aad::empty(), &mut in_out)
                    .map_err(|_| SeetleError::OperationError("Decryption failed".into()))?;

                Ok(decrypted_data.to_vec())
            }
        }
    }

    async fn digest(&self, _algorithm: Algorithm, _data: Vec<u8>) -> Result<Vec<u8>, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn import_key(&self, _format: String, _key_data: Vec<u8>, _algorithm: Algorithm, _extractable: bool, _key_usages: Vec<KeyUsage>) -> Result<CryptoKey, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn export_key(&self, _format: String, key: KeyOrIdentifier) -> Result<Vec<u8>, SeetleError> {
        let identifier = match key {
            KeyOrIdentifier::Identifier(id) => id,
            KeyOrIdentifier::Key(_) => return Err(SeetleError::NotSupported),
        };

        // Delegate to root backend if identifier matches
        if let RootKeySource::Backend { backend, identifier: root_id, .. } = &self.root_key_source {
            if identifier == *root_id {
                return backend.export_key(_format, KeyOrIdentifier::Identifier(identifier)).await;
            }
        }

        let item = self.get_metadata(&identifier).await?;
        match item {
            XHDStorageItem::Key(metadata) => {
                if !metadata.bindings.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                let context_enum = match metadata.context.as_str() {
                    "Address" => KeyContext::Address,
                    "Identity" => KeyContext::Identity,
                    _ => return Err(SeetleError::DataError),
                };
                let scheme_enum = match metadata.scheme.as_str() {
                    "Peikert" => DerivationScheme::Peikert,
                    "V2" => DerivationScheme::V2,
                    _ => return Err(SeetleError::DataError),
                };

                let root_key = self.get_root_key().await?;
                let derived_xprv = key_gen(&root_key, context_enum, metadata.account, metadata.key_index, scheme_enum)
                    .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;
                
                // For Ed25519 keys, raw export is the 32-byte secret seed (first 32 bytes of extended secret key)
                Ok(derived_xprv.extended_secret_key_bytes()[..32].to_vec())
            }
            XHDStorageItem::Standalone(metadata) => {
                if !metadata.bindings.extractable {
                    return Err(SeetleError::OperationError("Key is not extractable".into()));
                }
                Ok(metadata.seed)
            }
        }
    }

    async fn derive_key(&self, _algorithm: Algorithm, _base_key: KeyOrIdentifier, _derived_key_type: Algorithm, _extractable: bool, _key_usages: Vec<KeyUsage>) -> Result<KeyOrIdentifier, SeetleError> {
        Err(SeetleError::NotSupported)
    }

    async fn derive_bits(&self, algorithm: Algorithm, base_key: KeyOrIdentifier, length: u32) -> Result<Vec<u8>, SeetleError> {
        let id = match &base_key {
            KeyOrIdentifier::Identifier(id) => id,
            _ => return Err(SeetleError::NotSupported),
        };
        if let Some(backend) = self.get_root_backend_if_matches(id) {
            return backend.derive_bits(algorithm, base_key, length).await;
        }

        match algorithm {
            Algorithm::Ecdh { name, public_key } => {
                let id = match base_key {
                    KeyOrIdentifier::Identifier(id) => id,
                    _ => return Err(SeetleError::NotSupported),
                };
                let item = self.get_metadata(&id).await?;
                let metadata = match item {
                    XHDStorageItem::Key(m) => m,
                    _ => return Err(SeetleError::OperationError("ECDH requires a key".into())),
                };

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

                let root_key = self.get_root_key().await?;
                let derived_xprv = key_gen(&root_key, context, metadata.account, metadata.key_index, scheme)
                    .map_err(|e| SeetleError::OperationError(format!("Derivation error: {:?}", e)))?;

                // Convert Ed25519 secret key to X25519
                let xprv_bytes = derived_xprv.extended_secret_key_bytes();
                let mut scalar_bytes = [0u8; 32];
                scalar_bytes.copy_from_slice(&xprv_bytes[0..32]);
                let secret = StaticSecret::from(scalar_bytes);

                // Convert peer Ed25519 public key to X25519
                let peer_x25519_pub = if public_key.len() == 32 {
                    // Assume it's an Ed25519 public key, convert it
                    let compressed = CompressedEdwardsY::from_slice(&public_key)
                        .map_err(|_| SeetleError::DataError)?;
                    let edwards_point = compressed.decompress()
                        .ok_or(SeetleError::DataError)?;
                    let montgomery_point = edwards_point.to_montgomery();
                    PublicKey::from(montgomery_point.to_bytes())
                } else {
                    return Err(SeetleError::DataError);
                };

                let shared_secret = secret.diffie_hellman(&peer_x25519_pub);
                let shared_bytes = shared_secret.as_bytes().to_vec();

                // If name starts with "SAVE_KEY:", save as a new standalone key
                if name.starts_with("SAVE_KEY:") {
                    let save_id = &name[9..];
                    // Expand 32-byte shared secret to 64-byte seed for XPrv
                    // We'll use SHA256 to derive the second half (chain code)
                    let mut seed = [0u8; 64];
                    seed[0..32].copy_from_slice(&shared_bytes);
                    let chain_code = ring::digest::digest(&ring::digest::SHA256, &shared_bytes);
                    seed[32..64].copy_from_slice(chain_code.as_ref());

                    let standalone_metadata = StandaloneMetadata {
                        bindings: Bindings { identifier: save_id.to_string(), extractable: true, ..Default::default() },
                        algorithm: Algorithm::Ed25519 { name: "Ed25519".into() },
                        usages: vec![KeyUsage::Sign, KeyUsage::Verify, KeyUsage::Encrypt, KeyUsage::Decrypt],
                        seed: seed.to_vec(),
                        source_key_identifier: Some(id.to_string()),
                        context: Some("ECDH".into()),
                    };
                    let metadata_bytes = serde_json::to_vec(&XHDStorageItem::Standalone(standalone_metadata))
                        .map_err(|e| SeetleError::OperationError(e.to_string()))?;
                    self.storage.set_item(save_id, metadata_bytes).await?;
                }

                if length > (shared_bytes.len() * 8) as u32 {
                    return Err(SeetleError::OperationError("Requested length too long".into()));
                }

                Ok(shared_bytes[0..(length / 8) as usize].to_vec())
            }
            Algorithm::Hpke { .. } => {
                Err(SeetleError::NotSupported)
            }
            _ => Err(SeetleError::NotSupported),
        }
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
    use crate::memory::MemoryStorage;
    use crate::tpm::TpmStorage;

    const SEED: [u8; 64] = [0x42; 64];

    #[tokio::test]
    async fn test_xhd_backend_derivation_and_sign() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle: &dyn Seetle = &backend;

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
        let seetle: &dyn Seetle = &backend;

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
        
        #[cfg(feature = "tpm")]
        let secure_storage_res = {
            use crate::tpm::TpmBackend;
            match TpmBackend::create_context(None) {
                Ok(ctx) => TpmStorage::new(base_storage, ctx),
                Err(e) => Err(e),
            }
        };

        #[cfg(not(feature = "tpm"))]
        let secure_storage_res = TpmStorage::new(base_storage);
        
        let secure_storage = match secure_storage_res {
            Ok(s) => Arc::new(s),
            Err(_) => {
                #[cfg(feature = "tpm")]
                {
                    println!("Skipping test: TPM not available");
                    return;
                }
                #[cfg(not(feature = "tpm"))]
                panic!("TpmStorage::new should not fail when tpm feature is disabled");
            }
        };

        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(secure_storage, root_key);
        let seetle: &dyn Seetle = &backend;

        let algorithm = Algorithm::Ed25519 {
            name: "XHD:Address:0:0:Peikert".into(),
        };
        let bindings = Bindings {
            identifier: "secure-xhd-key".into(),
            ..Default::default()
        };

        // Key generation (metadata will be "wrapped" by TpmStorage)
        let key_id_res = seetle.generate_key(
            algorithm.clone(),
            false,
            Some(bindings),
            vec![KeyUsage::Sign],
        ).await;

        let key_id = match key_id_res {
            Ok(id) => id,
            Err(e) if e.to_string().contains("command code not supported") => {
                println!("Skipping test: TPM does not support EncryptDecrypt2");
                return;
            }
            Err(e) => panic!("Key generation failed: {:?}", e),
        };

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

    #[tokio::test]
    async fn test_xhd_with_backend_backed_root() {
        use crate::mock::MockBackend;

        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let mock_storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let mock_backend = Arc::new(MockBackend::new(mock_storage));

        // Create XHDBackend using MockBackend to provide the root key
        let backend = XHDBackend::new_with_backend(
            storage,
            mock_backend,
            "master-key".into(),
            Algorithm::Generic { name: "PBKDF2".into() },
        );
        let seetle: &dyn Seetle = &backend;

        let algorithm = Algorithm::Ed25519 {
            name: "XHD:Address:0:0:Peikert".into(),
        };
        let bindings = Bindings {
            identifier: "backend-xhd-key".into(),
            ..Default::default()
        };

        // This will trigger get_root_key() which calls mock_backend.derive_bits()
        let key_id = seetle.generate_key(
            algorithm.clone(),
            false,
            Some(bindings),
            vec![KeyUsage::Sign],
        ).await.unwrap();

        if let KeyOrIdentifier::Identifier(id) = key_id {
            assert_eq!(id, "backend-xhd-key");
            let data = b"hello from backend-backed xhd".to_vec();
            let signature = seetle.sign(algorithm, KeyOrIdentifier::Identifier(id), data).await.unwrap();
            assert_eq!(signature.len(), 64);
        } else {
            panic!("Expected identifier");
        }
    }

    #[tokio::test]
    async fn test_xhd_encrypt_decrypt() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle: &dyn Seetle = &backend;

        let algorithm = Algorithm::Ed25519 {
            name: "XHD:Address:0:0:Peikert".into(),
        };
        let bindings = Bindings {
            identifier: "test-encrypt".into(),
            ..Default::default()
        };

        let key_id = seetle.generate_key(
            algorithm.clone(),
            false,
            Some(bindings),
            vec![KeyUsage::Encrypt, KeyUsage::Decrypt],
        ).await.unwrap();

        let data = b"secret message".to_vec();
        let encrypted = seetle.encrypt(Algorithm::Generic { name: "ignored".into() }, key_id.clone(), data.clone()).await.unwrap();
        assert_ne!(encrypted, data);

        let decrypted = seetle.decrypt(Algorithm::Generic { name: "ignored".into() }, key_id, encrypted).await.unwrap();
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn test_xhd_ecdh() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle: &dyn Seetle = &backend;

        // 1. Generate two keys
        let alg1 = Algorithm::Ed25519 { name: "XHD:Address:0:1:Peikert".into() };
        let key1 = seetle.generate_key(alg1.clone(), false, Some(Bindings { identifier: "k1".into(), ..Default::default() }), vec![KeyUsage::DeriveBits]).await.unwrap();
        let meta1 = seetle.get_key_metadata("k1".into()).await.unwrap();
        let pub1 = meta1.public_key.unwrap();

        let alg2 = Algorithm::Ed25519 { name: "XHD:Address:0:2:Peikert".into() };
        let key2 = seetle.generate_key(alg2.clone(), false, Some(Bindings { identifier: "k2".into(), ..Default::default() }), vec![KeyUsage::DeriveBits]).await.unwrap();
        let meta2 = seetle.get_key_metadata("k2".into()).await.unwrap();
        let pub2 = meta2.public_key.unwrap();

        // 2. Perform ECDH from both sides
        let secret1 = seetle.derive_bits(Algorithm::Ecdh { name: "X25519".into(), public_key: pub2 }, key1, 256).await.unwrap();
        let secret2 = seetle.derive_bits(Algorithm::Ecdh { name: "X25519".into(), public_key: pub1 }, key2, 256).await.unwrap();

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 32);
    }

    #[tokio::test]
    async fn test_xhd_hpke() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle: &dyn Seetle = &backend;

        let alg = Algorithm::Ed25519 { name: "XHD:Address:0:1:Peikert".into() };
        let key_id = seetle.generate_key(alg, false, Some(Bindings { identifier: "recipient".into(), ..Default::default() }), vec![KeyUsage::Decrypt]).await.unwrap();
        let meta = seetle.get_key_metadata("recipient".into()).await.unwrap();
        let pub_key = meta.public_key.unwrap();

        let data = b"HPKE is cool".to_vec();
        let info = b"some context".to_vec();

        // 1. Seal
        let combined = seetle.encrypt(
            Algorithm::Hpke {
                name: "DHKEM_X25519_HKDF_SHA256".into(),
                public_key: Some(pub_key.clone()),
                info: Some(info.clone()),
            },
            KeyOrIdentifier::Identifier("ignored".into()),
            data.clone()
        ).await.unwrap();

        assert!(combined.len() > 32);

        // 2. Open
        let opened = seetle.decrypt(
            Algorithm::Hpke {
                name: "DHKEM_X25519_HKDF_SHA256".into(),
                public_key: None,
                info: Some(info.clone()),
            },
            key_id.clone(),
            combined
        ).await.unwrap();

        assert_eq!(opened, data);
    }


    #[tokio::test]
    async fn test_xhd_key_from_shared_secret() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle: &dyn Seetle = &backend;

        // 1. Generate two keys
        let alg1 = Algorithm::Ed25519 { name: "XHD:Address:0:1:Peikert".into() };
        let key1 = seetle.generate_key(alg1.clone(), false, Some(Bindings { identifier: "k1".into(), ..Default::default() }), vec![KeyUsage::DeriveBits]).await.unwrap();
        
        let alg2 = Algorithm::Ed25519 { name: "XHD:Address:0:2:Peikert".into() };
        let _key2 = seetle.generate_key(alg2.clone(), false, Some(Bindings { identifier: "k2".into(), ..Default::default() }), vec![KeyUsage::DeriveBits]).await.unwrap();
        let meta2 = seetle.get_key_metadata("k2".into()).await.unwrap();
        let pub2 = meta2.public_key.unwrap();

        // 2. Derive shared secret and save it as a NEW KEY
        seetle.derive_bits(Algorithm::Ecdh { name: "SAVE_KEY:new-key".into(), public_key: pub2 }, key1, 256).await.unwrap();

        // 3. Verify the new key exists and can sign
        let meta = seetle.get_key_metadata("new-key".into()).await.unwrap();
        assert_eq!(meta.context, Some("ECDH".to_string()));
        assert_eq!(meta.algorithm, "Ed25519 { name: \"Ed25519\" }".to_string());
        assert_eq!(meta.source_key_identifier, Some("k1".to_string()));
        assert!(meta.public_key.is_some());

        let data = b"test message".to_vec();
        let signature = seetle.sign(Algorithm::Ed25519 { name: "Ed25519".into() }, KeyOrIdentifier::Identifier("new-key".into()), data.clone()).await.unwrap();
        
        let verified = seetle.verify(Algorithm::Ed25519 { name: "Ed25519".into() }, KeyOrIdentifier::Identifier("new-key".into()), signature, data).await.unwrap();
        assert!(verified);
        
        // 4. Verify it can also be used for encryption/decryption
        let enc_data = b"secret".to_vec();
        let encrypted = seetle.encrypt(Algorithm::Generic { name: "AES-GCM".into() }, KeyOrIdentifier::Identifier("new-key".into()), enc_data.clone()).await.unwrap();
        let decrypted = seetle.decrypt(Algorithm::Generic { name: "AES-GCM".into() }, KeyOrIdentifier::Identifier("new-key".into()), encrypted).await.unwrap();
        assert_eq!(decrypted, enc_data);
    }

    #[tokio::test]
    async fn test_xhd_metadata_master_seed() {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::new());
        let root_key = XPrv::from_seed(&SEED);
        let backend = XHDBackend::new(storage, root_key);
        let seetle: &dyn Seetle = &backend;

        let alg = Algorithm::Ed25519 { name: "XHD:Address:0:1:Peikert".into() };
        seetle.generate_key(alg, true, Some(Bindings { identifier: "k1".into(), ..Default::default() }), vec![KeyUsage::Sign]).await.unwrap();

        let meta = seetle.get_key_metadata("k1".into()).await.unwrap();
        assert!(meta.extractable); // Direct keys are extractable

        // Test with backend root
        let root_storage = Arc::new(MemoryStorage::new());
        let root_backend_raw = crate::mock::backend::MockBackend::new(root_storage);
        root_backend_raw.generate_key(
            Algorithm::Generic { name: "seed".to_string() },
            true,
            Some(Bindings { identifier: "master-seed-id".to_string(), hardware_bound: HardwareBound::Yes, ..Default::default() }),
            vec![]
        ).await.unwrap();

        let root_backend: Arc<dyn Seetle> = Arc::new(root_backend_raw);
        let backend2 = XHDBackend::new_with_backend(
            Arc::new(MemoryStorage::new()),
            root_backend,
            "master-seed-id".to_string(),
            Algorithm::Generic { name: "seed".to_string() }
        );
        let seetle2: &dyn Seetle = &backend2;

        seetle2.generate_key(
            Algorithm::Ed25519 { name: "XHD:Address:0:1:Peikert".into() },
            false,
            Some(Bindings { identifier: "k2".into(), ..Default::default() }),
            vec![KeyUsage::Sign]
        ).await.unwrap();

        let meta2 = seetle2.get_key_metadata("k2".into()).await.unwrap();
        assert!(!meta2.extractable);
        
        // Root key is also available in list
        let keys = seetle2.list_keys().await.unwrap();
        assert!(keys.contains(&"master-seed-id".to_string()));
        
        // And can be accessed directly
        let meta_root = seetle2.get_key_metadata("master-seed-id".into()).await.unwrap();
        assert_eq!(meta_root.identifier, "master-seed-id");
        assert!(meta_root.extractable);
    }

    #[tokio::test]
    async fn test_xhd_partial_hardware_bound() {
        let root_storage = Arc::new(MemoryStorage::new());
        let root_backend_raw = crate::mock::backend::MockBackend::new(root_storage);
        root_backend_raw.generate_key(
            Algorithm::Generic { name: "seed".to_string() },
            true,
            Some(Bindings { identifier: "master-seed-id".to_string(), hardware_bound: HardwareBound::Yes, ..Default::default() }),
            vec![]
        ).await.unwrap();

        let root_backend: Arc<dyn Seetle> = Arc::new(root_backend_raw);
        let backend = XHDBackend::new_with_backend(
            Arc::new(MemoryStorage::new()),
            root_backend,
            "master-seed-id".to_string(),
            Algorithm::Generic { name: "seed".to_string() }
        );
        let seetle: &dyn Seetle = &backend;

        let alg = Algorithm::Ed25519 { name: "XHD:Address:0:1:Peikert".into() };
        seetle.generate_key(alg, true, Some(Bindings { identifier: "k1".into(), ..Default::default() }), vec![KeyUsage::Sign]).await.unwrap();

        let meta = seetle.get_key_metadata("k1".into()).await.unwrap();
        assert_eq!(meta.hardware_bound, HardwareBound::Partial);

        // Master seed should also be partially bound in this context
        let meta_root = seetle.get_key_metadata("master-seed-id".into()).await.unwrap();
        assert_eq!(meta_root.hardware_bound, HardwareBound::Partial);
    }
}
