# Seelte

`seelte` is a Rust library providing a pluggable, WebCrypto-like API designed to safely handle cryptographic materials. It implements the [Hardware-Backed WebCrypto Extension](https://github.com/brave-experiments/hardware-backed-webcrypto) proposal. 

By defining abstract backends and secure storage integration, `seelte` enables operations with hardware-bound keys across origins without exposing the key material itself.

## Features

- **WebCrypto-style API:** Implements familiar WebCrypto Subtle methods (`generate_key`, `sign`, `verify`, `encrypt`, `decrypt`, etc.) inside a unified trait.
- **Hardware-bound Keys:** Support for hardware-backed keys, storing origin bindings and unique identifiers persistently. Keys marked as hardware-bound cannot be extracted, providing strong isolation and hardware-level security guarantees.
- **Pluggable Backends:** Inject custom storage or cryptographic modules implementing the `Backend` and `SecureStorage` traits to orchestrate different KMS, HSM, or system keychain mechanisms seamlessly. Includes:
   - **[Nordic Semiconductor](docs/nordic.md):** Leveraging Arm CryptoCell via PSA Crypto.
   - **[Keyring](docs/keyring.md):** Utilizing system-level secure credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service) with `ring` for cryptographic operations.
   - **[Secure Environment](docs/secure_env.md):** Hardware-backed key management for Android (KeyStore) and iOS (Secure Enclave) using the `secure-env` crate.
   - **[Tropic Square](docs/tropic.md):** Supporting TROPIC01 secure element via `libtropic`.
   - **[Mock Backend](docs/mock.md):** In-memory backend for testing.
- **Async Runtime:** Fully asynchronous using `tokio`, allowing integration into highly-concurrent web servers or network clients.

## Supported Backends

| Backend | Platform | Key Storage | Crypto Engine | Hardware Bound |
|---|---|---|---|---|
| [`NordicBackend`](docs/nordic.md) | Nordic SoCs | PSA ITS / PSA Key | CryptoCell / PSA | Yes |
| [`KeyringBackend`](docs/keyring.md) | Desktop (macOS/Win/Linux) | OS Keychain | `ring` | Partial* |
| [`SecureEnvBackend`](docs/secure_env.md) | Mobile (Android/iOS) | KeyStore / Secure Enclave | OS Secure Environment | Yes |
| [`TropicBackend`](docs/tropic.md) | Any (w/ TROPIC01) | TROPIC01 R-Mem | TROPIC01 SPECT | Yes |
| [`MockBackend`](docs/mock.md) | Any | In-memory | Mock (Fake data) | No |

*\*KeyringBackend stores key material in the OS keychain. While the keychain is secure, the cryptographic operations happen in the library memory (via `ring`), unlike `NordicBackend` or `SecureEnvBackend` where the key material never leaves the hardware.*

## Usage

Here's an example of how you can configure and use the `seelte` API with the `KeyringBackend`:

```rust
use seelte::{Algorithm, Bindings, KeyUsage, Seelte};
use seelte::backends::{KeyringBackend, MemoryStorage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), seelte::SeetleError> {
    // 1. Initialize storage and backend
    let storage = Arc::new(MemoryStorage::new());
    let backend = KeyringBackend::new(storage);
    let seelte = Seelte::new(backend);

    // 2. Define key bindings
    let bindings = Bindings {
        hardware_bound: true,
        origin_bindings: vec!["https://example.com".to_string()],
        identifier: "user-auth-key-1".to_string(),
        updatable: true,
    };

    // 3. Generate a hardware-bound key
    let key_ref = seelte.seetle().generate_key(
        Algorithm::Ecdsa {
            name: "ECDSA".to_string(),
            named_curve: "P-256".to_string(),
            hash: Some("SHA-256".to_string()),
        }, 
        false, 
        Some(bindings), 
        vec![KeyUsage::Sign]
    ).await?;

    Ok(())
}
```

### Advanced: Implementing a Custom Backend

To use `seelte` with a custom provider, you need to implement `Backend` and `SecureStorage` traits. Here is a simple in-memory example:

```rust
use seelte::{Algorithm, Bindings, KeyUsage, Seelte, Backend, SecureStorage, Seetle, KeyOrIdentifier, SeetleError, CryptoKey, KeyType};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;

// 1. Implement SecureStorage for persistence
struct MemoryStorage {
    items: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

#[async_trait]
impl SecureStorage for MemoryStorage {
    async fn get_item(&self, key: &str) -> Result<Option<Vec<u8>>, SeetleError> {
        Ok(self.items.lock().await.get(key).cloned())
    }
    async fn set_item(&self, key: &str, value: Vec<u8>) -> Result<(), SeetleError> {
        self.items.lock().await.insert(key.to_string(), value);
        Ok(())
    }
    async fn remove_item(&self, key: &str) -> Result<(), SeetleError> {
        self.items.lock().await.remove(key);
        Ok(())
    }
}

// 2. Implement Backend and Seetle
struct MyBackend {
    storage: Arc<dyn SecureStorage>,
}

impl Backend for MyBackend {
    fn seetle(&self) -> &dyn Seetle { self }
}

#[async_trait]
impl Seetle for MyBackend {
    async fn generate_key(
        &self,
        algorithm: Algorithm,
        extractable: bool,
        bindings: Option<Bindings>,
        _key_usages: Vec<KeyUsage>,
    ) -> Result<KeyOrIdentifier, SeetleError> {
        if let Some(b) = bindings {
            // Store metadata in secure storage
            let metadata = serde_json::to_vec(&b).map_err(|e| SeetleError::OperationError(e.to_string()))?;
            self.storage.set_item(&b.identifier, metadata).await?;
            Ok(KeyOrIdentifier::Identifier(b.identifier))
        } else {
            // ... standard key generation ...
            Ok(KeyOrIdentifier::Key(CryptoKey {
                key_type: KeyType::Secret,
                extractable,
                algorithm,
                usages: vec![],
            }))
        }
    }
    // ... implement other Seetle methods (sign, verify, etc.) ...
    async fn sign(&self, _a: Algorithm, _k: KeyOrIdentifier, _d: Vec<u8>) -> Result<Vec<u8>, SeetleError> { Ok(vec![]) }
}
```

### Example: Using the Custom Backend

```rust
#[tokio::main]
async fn main() -> Result<(), seelte::SeetleError> {
    let storage = Arc::new(MemoryStorage { items: Arc::new(Mutex::new(HashMap::new())) });
    let backend = MyBackend { storage };
    let seelte = Seelte::new(backend);

    let bindings = Bindings {
        hardware_bound: true,
        origin_bindings: vec!["https://example.com".to_string()],
        identifier: "user-auth-key-1".to_string(),
        updatable: true,
    };

    // Generate a hardware-bound key
    let key_ref = seelte.seetle().generate_key(
        Algorithm::Ecdsa {
            name: "ECDSA".to_string(),
            named_curve: "P-256".to_string(),
            hash: Some("SHA-256".to_string()),
        }, 
        false, 
        Some(bindings), 
        vec![KeyUsage::Sign]
    ).await?;

    Ok(())
}
```

## Extending WebCrypto

Unlike the standard browser-based WebCrypto specification, `seelte` provides mechanisms like `update_key` and `delete_key` to manage hardware credentials continuously as keys transition between policies and origin relationships. It uses `KeyOrIdentifier` enums throughout cryptographic routines to execute hardware-level functions by just using handles/references.

## License

This project is licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.


### Tropic Square Backend (feature-gated)

For detailed information, see the [TropicBackend Documentation](docs/tropic.md).

- A `TropicBackend` integrating the TROPIC01 secure element via `libtropic` is available behind the `tropic` Cargo feature.
- To enable it, build with: `cargo build --features tropic`.
- Notes:
  - The default build does not compile/link `libtropic` to keep host development simple.
  - The provided CMake integration builds `libtropic` with the mock HAL and Trezor Crypto CAL under `libtropic_build/`. For real hardware, point the build to the appropriate HAL (e.g., Linux SPI) and platform toolchain.
  - The backend focuses on ECDSA P-256 keys (key generation, signing). Verification on host uses `ring` with the public key from the device.
  - On unsupported targets or when the feature is disabled, `TropicBackend` methods return `SeetleError::NotSupported`.
