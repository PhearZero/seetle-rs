### Secure Environment Backend

The `SecureEnvBackend` integrates with the `secure-env` crate to provide hardware-backed key operations on mobile platforms (Android and iOS).

#### Features
- **Hardware-backed operations**: Uses Android Keystore and iOS Secure Enclave for key generation and signing.
- **Support for ECDSA**: ECDSA P-256 with SHA-256.
- **Hardware-Bound Keys**: Keys generated in the secure environment are non-exportable by design.

#### Prerequisites
- **Target Platform**: Only available on Android and iOS. On other platforms, it returns `SeetleError::NotSupported`.

#### Configuration (Cargo.toml)
To use the `SecureEnvBackend`, you must ensure that your dependencies are correctly configured for mobile targets:
```toml
[target.'cfg(any(target_os = "android", target_os = "ios"))'.dependencies]
secure-env = { package = "animo-secure-env", version = "0.5.0" }
```

#### Usage Example
```rust
use seelte::backends::SecureEnvBackend;
use seelte::storage::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = SecureEnvBackend::new(storage);

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```

#### Secure Environment-Backed Storage (SecureEnvStorage)

`SecureEnvStorage` is a decorator for mobile platforms that provides a skeleton for hardware-backed wrapping (encryption) of metadata. It is designed to use Android Keystore or iOS Secure Enclave features to protect any `SecureStorage` implementation.

```rust
use seelte::storage::{MemoryStorage, SecureEnvStorage};
use seelte::backends::xhd::XHDBackend;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let secure_storage = Arc::new(SecureEnvStorage::new(base_storage, "master-key-id").unwrap());

let root_key = XPrv::from_seed(&[0u8; 64]);
let xhd_backend = XHDBackend::new(secure_storage, root_key);
```

> **Note**: In the current version of the `secure-env` crate, this storage decorator acts as a skeleton and does not yet perform hardware-backed encryption, as the library currently focuses on signing operations.
