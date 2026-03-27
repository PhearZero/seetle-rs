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
use seelte::backends::mock::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = KeyringBackend::new(storage);

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```
