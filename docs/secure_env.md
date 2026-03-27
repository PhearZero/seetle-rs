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
use seelte::backends::mock::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = SecureEnvBackend::new(storage);

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```
