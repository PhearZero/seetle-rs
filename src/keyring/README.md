### Keyring Backend

The `KeyringBackend` provides hardware-backed (or OS-secured) key management by leveraging the platform's native keyring service.

#### Features
- **OS-Secured Storage**: Keys are stored using the system's built-in secure storage mechanisms.
- **Cross-Platform Support**: Works on macOS, Windows, and Linux.
- **Secure Key Access**: Keys are managed by the OS, and access can be restricted to authorized applications or users.
- **Support for ECDSA**: ECDSA P-256 with SHA-256 for signing and verification.
- **Support for Ed25519**: Ed25519 for signing and verification.

#### Platform Backends
The `KeyringBackend` uses the following native services via the `keyring` crate:
- **macOS**: Apple Keychain.
- **Windows**: Windows Credential Locker.
- **Linux**: Secret Service (GNOME Keyring, KWallet) or `keyutils` on headless systems.

#### Prerequisites
- **Linux**: Requires a Secret Service provider (e.g., `gnome-keyring`, `kwallet`) and a running D-Bus session bus. On some systems, `libdbus-1-dev` may be needed for compilation.

#### Persistence and Environment
For `KeyringBackend` and `KeyringStorage` to persist secrets between sessions, your environment must meet certain criteria:

- **Linux**:
    - A Secret Service provider must be installed and running.
    - A D-Bus session bus must be available (usually provided by `dbus-daemon` or `dbus-broker`).
    - If no Secret Service is available, it may fall back to the kernel `keyutils`, which has limited persistence (often cleared on logout).
- **macOS**: Apple Keychain is used and works out-of-the-box in interactive sessions.
- **Windows**: Windows Credential Locker is used and works out-of-the-box.

#### Troubleshooting
If you encounter "KeyNotFound" errors or decryption failures after a restart:
1. Ensure your keyring is unlocked.
2. Verify that a D-Bus session is active (e.g., check `DBUS_SESSION_BUS_ADDRESS`).
3. In headless Linux environments (CI/CD), secrets may not persist between processes if a persistent Secret Service is not available.

#### Usage Example
```rust
use seetle::keyring::KeyringBackend;
use seetle::memory::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = KeyringBackend::new(storage);

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```

#### Keyring-Backed Storage (KeyringStorage)

`KeyringStorage` is a decorator that can wrap any `SecureStorage` implementation. It uses the system's keyring to store and manage a master encryption key, providing hardware-protected (or OS-secured) confidentiality to any metadata.

```rust
use seetle::memory::MemoryStorage;
use seetle::keyring::KeyringStorage;
use seetle::xhd::XHDBackend;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let secure_storage = Arc::new(KeyringStorage::new(base_storage, "myapp", "master-storage-key").unwrap());

let root_key = XPrv::from_seed(&[0u8; 64]);
let xhd_backend = XHDBackend::new(secure_storage, root_key);
```

This allows you to leverage the OS keychain to protect sensitive metadata for *any* backend, even if that backend doesn't support hardware keys itself.
