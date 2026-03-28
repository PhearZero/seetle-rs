# Seetle

`seetle` is a Rust library providing a pluggable, WebCrypto-like API designed to safely handle cryptographic materials. It implements the [Hardware-Backed WebCrypto Extension](https://github.com/brave-experiments/hardware-backed-webcrypto) proposal. 

By defining abstract backends and secure storage integration, `seetle` enables operations with hardware-bound keys across origins without exposing the key material itself.

## Features

- **WebCrypto-style API:** Implements familiar WebCrypto Subtle methods (`generate_key`, `sign`, `verify`, `encrypt`, `decrypt`, etc.) inside a unified trait.
- **Hardware-bound Keys:** Support for hardware-backed keys, storing origin bindings and unique identifiers persistently. Keys marked as hardware-bound cannot be extracted, providing strong isolation and hardware-level security guarantees.
- **Pluggable Backends & Storage:** Inject custom storage or cryptographic modules implementing the `Backend` and `SecureStorage` traits. The `seetle` library provides various storage implementations:
   - **[MemoryStorage](src/mock/README.md):** Simple in-memory storage for testing.
   - **[TpmStorage](src/tpm/README.md):** Decorator that adds TPM-backed hardware protection (wrapping) to any storage implementation.
   - **[KeyringStorage](src/keyring/README.md):** Decorator that adds OS-secured (Keychain/Credential Manager) protection to any storage.
   - **[SecureEnvStorage](src/secure_env/README.md):** Decorator for mobile hardware-backed metadata protection.
   - **Backends:**
     - **[Nordic Semiconductor](src/nordic/README.md):** Leveraging Arm CryptoCell via PSA Crypto.
     - **[Keyring](src/keyring/README.md):** Utilizing system-level secure credential storage.
     - **[Secure Environment](src/secure_env/README.md):** Android/iOS hardware-backed key management.
     - **[Tropic Square](src/tropic/README.md):** TROPIC01 secure element integration.
     - **[TPM 2.0](src/tpm/README.md):** TPM-backed keys.
     - **[XHD Wallet](src/xhd/README.md):** Hierarchical Deterministic Ed25519 wallets.
     - **[Mock Backend](src/mock/README.md):** In-memory backend for testing.
- **Async Runtime:** Fully asynchronous using `tokio`, allowing integration into highly-concurrent web servers or network clients.

## CLI Usage

The library includes a CLI tool for hardware-backed key management on desktop platforms.

### Installation

```bash
cargo build --release
```

To enable optional features like TPM 2.0 or Keyring support:

```bash
# For TPM 2.0 support (requires tpm2-tss libraries)
cargo build --release --features tpm

# For Tropic Square support
cargo build --release --features tropic
```

### System Dependencies

#### TPM 2.0 (Linux)
Requires the TPM2-TSS software stack. On Ubuntu/Debian:
```bash
sudo apt install libtss2-dev tpm2-tools
```
Ensure your user has access to `/dev/tpmrm0` (usually by being in the `tss` group).

#### Keyring (Linux)
Requires a Secret Service provider (e.g., `gnome-keyring`, `kwallet`) and a running D-Bus session bus for persistent storage. On some systems, `libdbus-1-dev` may be needed for compilation.

### Examples

```bash
# Generate a key using XHD backend with Keyring root
./target/release/seetle generate-key --identifier my-key --root-backend keyring

# Sign data
./target/release/seetle sign --identifier my-key --data "Hello, world!"

# Verify signature
./target/release/seetle verify --identifier my-key --data "Hello, world!" --signature <HEX_SIGNATURE>
```

### Options

- `-s, --storage-dir <DIR>`: Directory for key metadata (default: `seetle-keystore`)
- `-w, --storage-wrapper <TYPE>`: Secure storage wrapper (`keyring` (default), `tpm`, or `none`)
- `-r, --root-backend <TYPE>`: Root backend for XHD derivation (`keyring` (default), `tpm`, or `mock`)

## Supported Backends

The following backends implement the `Seetle` trait, providing cryptographic operations with varying degrees of hardware isolation and storage strategies. All backends use the `SecureStorage` trait to manage metadata such as origin bindings and key identifiers.

| Backend | Platform | Key Material Storage | Metadata Storage | Hardware Bound |
|---|---|---|---|---|
| [`NordicBackend`](src/nordic/README.md) | Nordic SoCs | PSA ITS / PSA Key | `SecureStorage` | Yes |
| [`KeyringBackend`](src/keyring/README.md) | Desktop (macOS/Win/Linux) | OS Keychain | `SecureStorage` | Partial* |
| [`SecureEnvBackend`](src/secure_env/README.md) | Mobile (Android/iOS) | KeyStore / Secure Enclave | `SecureStorage` | Yes |
| [`TpmBackend`](src/tpm/README.md) | Desktop/Server (TPM 2.0) | `SecureStorage` (wrapped) | `SecureStorage` | Yes |
| [`TropicBackend`](src/tropic/README.md) | Any (w/ TROPIC01) | TROPIC01 R-Mem | `SecureStorage` | Yes |
| [`XHDBackend`](src/xhd/README.md) | Any | `SecureStorage` (root) | `SecureStorage` | No (HD) |
| [`MockBackend`](src/mock/README.md) | Any | `SecureStorage` | `SecureStorage` | No |

*\*KeyringBackend stores key material in the OS keychain. While the keychain is secure, the cryptographic operations happen in the library memory (via `ring`), unlike `NordicBackend` or `SecureEnvBackend` where the key material never leaves the hardware.*

## Storage Architecture & Composition

The `seetle` library decouples key material management from metadata persistence (like origin bindings and labels) through the `SecureStorage` trait. This modular approach allows for powerful storage composition and, in some contexts, the storage itself can be used to store raw key material securely.

### Available Storage Implementations

| Storage | Description | Hardware Protected |
|---|---|---|
| [`MemoryStorage`](src/mock/README.md) | Simple in-memory storage, ideal for testing and ephemeral keys. | No |
| [`TpmStorage`](src/tpm/README.md) | A decorator that adds TPM 2.0-backed encryption (wrapping) to *any* other storage implementation. Can be used for metadata and key material. | **Yes** |
| [`KeyringStorage`](src/keyring/README.md) | A decorator that uses the OS's secure keyring (Keychain/Credential Manager) to protect any storage. | **Yes** (OS-Secured) |
| [`SecureEnvStorage`](src/secure_env/README.md) | A decorator for mobile platforms providing hardware-backed protection for metadata. | **Yes** (Android/iOS) |
| Custom | Any implementation of the `SecureStorage` trait. | Varies |

### Storage-based Key Material

Some backends use `SecureStorage` not just for metadata but also for key material:

*   **[`MockBackend`](src/mock/README.md):** Stores all cryptographic keys in the provided storage. Using `TpmStorage` or `KeyringStorage` here provides hardware-wrapped or OS-secured keys.
*   **[`XHDBackend`](src/xhd/README.md):** Stores its HD wallet root key (seed) in the provided storage. This allows for hardware-backed (wrapped) seeds.
*   **[`TpmBackend`](src/tpm/README.md):** Stores its TPM-wrapped private key blobs in the storage, ensuring the keys remain bound to the hardware but are persisted flexibly.

### Storage Compatibility Matrix

All `seetle` backends are fully compatible with any implementation of the `SecureStorage` trait.

| Backend | `MemoryStorage` | `TpmStorage` | `KeyringStorage` | `SecureEnvStorage` |
|---|:---:|:---:|:---:|:---:|
| [`NordicBackend`](src/nordic/README.md) | ✓ | ✓* | ✓ | ✓ |
| [`KeyringBackend`](src/keyring/README.md) | ✓ | ✓ | ✓ | ✓ |
| [`SecureEnvBackend`](src/secure_env/README.md) | ✓ | ✓* | ✓ | ✓ |
| [`TpmBackend`](src/tpm/README.md) | ✓ | ✓ | ✓ | ✓ |
| [`TropicBackend`](src/tropic/README.md) | ✓ | ✓ | ✓ | ✓ |
| [`XHDBackend`](src/xhd/README.md) | ✓ | ✓ | ✓ | ✓ |
| [`MockBackend`](src/mock/README.md) | ✓ | ✓ | ✓ | ✓ |

*\*Compatibility depends on the availability of the underlying hardware (e.g., TPM 2.0) on the target platform. While the code is compatible, initializing `TpmStorage` on a platform without a TPM will result in a runtime error.*

### Example: Protecting XHD Wallets with TPM

You can use `TpmStorage` to ensure that your sensitive metadata (like the root key of an `XHDBackend` or its derivation paths) is protected by hardware encryption, even when stored in a standard database or in memory:

```rust
use seetle::memory::MemoryStorage;
use seetle::tpm::TpmStorage;
use seetle::xhd::XHDBackend;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a base storage (e.g., in-memory)
    let base_storage = Arc::new(MemoryStorage::new());

    // 2. Wrap it with TPM protection
    // All items stored in tpm_storage will be encrypted by the TPM
    let tpm_storage = Arc::new(TpmStorage::new(base_storage)?);

    // 3. Use the TPM-protected storage with your chosen backend
    let root_key = xhd_wallet_api::XPrv::from_seed(&[0u8; 64]);
    let backend = XHDBackend::new(tpm_storage, root_key);
    
    // Now, any key generated or metadata stored via this backend 
    // is transparently encrypted/decrypted by the TPM hardware.
    Ok(())
}
```

### Example: Hardware-Backed Metadata for Keyring

Even though `KeyringBackend` stores key material in the OS keychain, you can use `TpmStorage` to protect your origin bindings and other metadata in a hardware-isolated way:

```rust
use seetle::memory::MemoryStorage;
use seetle::tpm::TpmStorage;
use seetle::keyring::KeyringBackend;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let tpm_storage = Arc::new(TpmStorage::new(base_storage)?);

// Origin bindings and key IDs are now wrapped by TPM
let backend = KeyringBackend::new(tpm_storage);
```

## Usage

Here's an example of how you can configure and use the `seetle` API with the `KeyringBackend`:

```rust
use seetle::{Algorithm, Bindings, KeyUsage, Seetle};
use seetle::keyring::KeyringBackend;
use seetle::memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), seetle::SeetleError> {
    // 1. Initialize storage and backend
    let storage = Arc::new(MemoryStorage::new());
    let backend = KeyringBackend::new(storage);
    let seetle = Seetle::new(backend);

    // 2. Define key bindings
    let bindings = Bindings {
        hardware_bound: true,
        origin_bindings: vec!["https://example.com".to_string()],
        identifier: "user-auth-key-1".to_string(),
        updatable: true,
    };

    // 3. Generate a hardware-bound key
    let key_ref = seetle.seetle().generate_key(
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

To use `seetle` with a custom provider, you need to implement `Backend` and `SecureStorage` traits. Here is a simple in-memory example:

```rust
use seetle::{Algorithm, Bindings, KeyUsage, Seetle, Backend, SecureStorage, Seetle, KeyOrIdentifier, SeetleError, CryptoKey, KeyType};
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

// 2. Implement Seetle trait
struct MyBackend {
    storage: Arc<dyn SecureStorage>,
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
async fn main() -> Result<(), seetle::SeetleError> {
    let storage = Arc::new(MemoryStorage { items: Arc::new(Mutex::new(HashMap::new())) });
    let backend = MyBackend { storage };
    let seetle = Seetle::new(backend);

    let bindings = Bindings {
        hardware_bound: true,
        origin_bindings: vec!["https://example.com".to_string()],
        identifier: "user-auth-key-1".to_string(),
        updatable: true,
    };

    // Generate a hardware-bound key
    let key_ref = seetle.seetle().generate_key(
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

Unlike the standard browser-based WebCrypto specification, `seetle` provides mechanisms like `update_key` and `delete_key` to manage hardware credentials continuously as keys transition between policies and origin relationships. It uses `KeyOrIdentifier` enums throughout cryptographic routines to execute hardware-level functions by just using handles/references.

### Composition: Hardware-Protected Metadata

You can compose storage and backends for enhanced security. For example, using the `TpmStorage` decorator with the `XHDBackend` to wrap hierarchical derivation paths in hardware:

```rust
use seetle::xhd::XHDBackend;
use seetle::memory::MemoryStorage;
use seetle::tpm::TpmStorage;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let secure_storage = Arc::new(TpmStorage::new(base_storage).unwrap());

let root_key = XPrv::from_seed(&[0u8; 64]);
let backend = XHDBackend::new(secure_storage, root_key);
```

This project is licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.


### Tropic Square Backend (feature-gated)

For detailed information, see the [TropicBackend Documentation](src/tropic/README.md).

- A `TropicBackend` integrating the TROPIC01 secure element via `libtropic` is available behind the `tropic` Cargo feature.
- To enable it, build with: `cargo build --features tropic`.
- Notes:
  - The default build does not compile/link `libtropic` to keep host development simple.
  - The provided CMake integration builds `libtropic` with the mock HAL and Trezor Crypto CAL under `libtropic_build/`. For real hardware, point the build to the appropriate HAL (e.g., Linux SPI) and platform toolchain.
  - The backend focuses on ECDSA P-256 keys (key generation, signing). Verification on host uses `ring` with the public key from the device.
  - On unsupported targets or when the feature is disabled, `TropicBackend` methods return `SeetleError::NotSupported`.
