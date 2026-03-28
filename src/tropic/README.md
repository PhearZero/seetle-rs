### Tropic Square Backend

The `TropicBackend` provides hardware-backed key management using the TROPIC01 secure element by Tropic Square.

#### Features
- **Secure Element Integration**: Directly interfaces with the TROPIC01 hardware via the `tropic01` Rust crate.
- **Hardware-bound Keys**: Keys are generated and stored within the TROPIC01 secure element.
- **Support for ECDSA and Ed25519**: P-256 and Ed25519 signing. Verification is performed on the host using the `ring` crate.

#### Build Configuration
To enable the Tropic backend, build the project with the `tropic` feature:

```bash
cargo build --features tropic
```

The build process uses the `tropic01` crate as a dependency. By default, it uses a mock HAL for SPI. For production use with real hardware, you may need to provide a real implementation of the `embedded-hal` traits for your platform.

#### Usage Example
```rust
use seetle::tropic::TropicBackend;
use seetle::memory::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = TropicBackend::new(storage).expect("Failed to initialize TropicBackend");

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```

#### Metadata Protection with TPM

You can use `TpmStorage` to protect your TROPIC01 key slot metadata and origin bindings:

```rust
use seetle::memory::MemoryStorage;
use seetle::tpm::TpmStorage;
use seetle::tropic::TropicBackend;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let tpm_storage = Arc::new(TpmStorage::new(base_storage).unwrap());

// TROPIC01 metadata is now wrapped by TPM
let backend = TropicBackend::new(tpm_storage).unwrap();
```
