### Keyring Backend

The `KeyringBackend` provides hardware-backed (or OS-secured) key management by leveraging the platform's native keyring service.

#### Features
- **OS-Secured Storage**: Keys are stored using the system's built-in secure storage mechanisms.
- **Cross-Platform Support**: Works on macOS, Windows, and Linux.
- **Secure Key Access**: Keys are managed by the OS, and access can be restricted to authorized applications or users.
- **Support for ECDSA**: ECDSA P-256 with SHA-256 for signing and verification.

#### Platform Backends
The `KeyringBackend` uses the following native services via the `keyring` crate:
- **macOS**: Apple Keychain.
- **Windows**: Windows Credential Locker.
- **Linux**: Secret Service (GNOME Keyring, KWallet) or `keyutils` on headless systems.

#### Prerequisites
- **Linux**: Requires `libdbus-1-dev` for the Secret Service integration.

#### Usage Example
```rust
use seelte::backends::KeyringBackend;
use seelte::storage::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = KeyringBackend::new(storage);

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```

#### Keyring-Backed Storage (KeyringStorage)

`KeyringStorage` is a decorator that can wrap any `SecureStorage` implementation. It uses the system's keyring to store and manage a master encryption key, providing hardware-protected (or OS-secured) confidentiality to any metadata.

```rust
use seelte::storage::{MemoryStorage, KeyringStorage};
use seelte::backends::xhd::XHDBackend;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let secure_storage = Arc::new(KeyringStorage::new(base_storage, "myapp", "master-storage-key").unwrap());

let root_key = XPrv::from_seed(&[0u8; 64]);
let xhd_backend = XHDBackend::new(secure_storage, root_key);
```

This allows you to leverage the OS keychain to protect sensitive metadata for *any* backend, even if that backend doesn't support hardware keys itself.
