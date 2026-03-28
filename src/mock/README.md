### Mock Backend

The `MockBackend` provides an in-memory implementation of the `Seetle` trait for testing and development purposes.

#### Features
- **In-Memory Storage**: Keys are stored in memory and are lost when the backend instance is destroyed.
- **Support for ECDSA**: ECDSA P-256 with SHA-256 (using the `ring` crate).
- **Fast and Predictable**: Ideal for unit and integration testing where hardware backends are not available.

#### Usage Example
```rust
use seetle::mock::MockBackend;
use seetle::memory::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = MockBackend::new(storage);

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```

### MemoryStorage and TpmStorage

The `MockBackend` is typically used with `MemoryStorage` for testing. However, it can also be used with any `SecureStorage` implementation, including `TpmStorage`:

```rust
use seetle::memory::MemoryStorage;
use seetle::tpm::TpmStorage;
use seetle::mock::MockBackend;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let tpm_storage = Arc::new(TpmStorage::new(base_storage).unwrap());

// Even mock metadata is now wrapped by TPM
let backend = MockBackend::new(tpm_storage);
```
