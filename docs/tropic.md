### Tropic Square Backend

The `TropicBackend` provides hardware-backed key management using the TROPIC01 secure element by Tropic Square.

#### Features
- **Secure Element Integration**: Directly interfaces with the TROPIC01 hardware via `libtropic`.
- **Hardware-bound Keys**: Keys are generated and stored within the TROPIC01 secure element.
- **Support for ECDSA**: ECDSA P-256 with SHA-256 for signing. Verification is performed on the host using the `ring` crate.

#### Prerequisites
- **TROPIC01 Hardware**: Access to a TROPIC01 secure element or a compatible development board.
- **libtropic SDK**: The C SDK for TROPIC01 must be cloned into the project root.

#### Installation
Since the `libtropic` SDK is not included in this repository, you must clone it manually into the `libtropic` directory:

```bash
git clone https://github.com/tropicsquare/libtropic.git
```

Ensure you are using a version compatible with this library (e.g., `v3.2.0` or later).

#### Build Configuration
To enable the Tropic backend, build the project with the `tropic` feature:

```bash
cargo build --features tropic
```

The build process uses CMake to compile the `libtropic` SDK and link it with the `seelte` library. By default, it uses a mock HAL and Trezor Crypto CAL. For production use with real hardware, you may need to modify the CMake configuration in `libtropic_build/CMakeLists.txt` to point to the correct HAL (e.g., Linux SPI) and toolchain.

#### Usage Example
```rust
use seelte::backends::TropicBackend;
use seelte::storage::MemoryStorage; // Or any implementation of SecureStorage
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = TropicBackend::new(storage).expect("Failed to initialize TropicBackend");

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```

#### Metadata Protection with TPM

You can use `TpmStorage` to protect your TROPIC01 key slot metadata and origin bindings:

```rust
use seelte::storage::{MemoryStorage, TpmStorage};
use seelte::backends::TropicBackend;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let tpm_storage = Arc::new(TpmStorage::new(base_storage).unwrap());

// TROPIC01 metadata is now wrapped by TPM
let backend = TropicBackend::new(tpm_storage).unwrap();
```
