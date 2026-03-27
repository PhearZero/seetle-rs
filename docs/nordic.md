### Nordic Backend

The `NordicBackend` provides hardware-backed key management leveraging the Arm CryptoCell hardware accelerator and the PSA Crypto API available on Nordic Semiconductor SoCs.

#### Features
- **Hardware-backed storage**: Keys are stored securely and managed by the hardware.
- **Support for ECDSA**: ECDSA P-256 with SHA-256.
- **Support for RSA-PSS**: RSA-PSS with SHA-256.
- **Support for AES-GCM**: AES-GCM encryption/decryption.
- **PSA Crypto API integration**: Directly interfaces with the Platform Security Architecture (PSA) standard.

#### Prerequisites
- **nRF Connect SDK (NCS)**: This backend is specifically designed to run within the nRF Connect SDK environment.
- **Hardware Support**: Compatible with Nordic SoCs featuring Arm CryptoCell (e.g., nRF52840, nRF9160, nRF5340).

#### Configuration
To use the `NordicBackend`, ensure your NCS project configuration includes the following options (usually in `prj.conf`):
```conf
CONFIG_PSA_CRYPTO_DRIVER_CC3XX=y
CONFIG_PSA_CRYPTO_CLIENT=y
CONFIG_NORDIC_SECURITY_BACKEND=y
```

#### Usage Example
```rust
use seelte::backends::NordicBackend;
use seelte::backends::mock::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = NordicBackend::new(storage);

// Initialize PSA subsystem before use
backend.init().expect("Failed to initialize PSA subsystem");

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```
