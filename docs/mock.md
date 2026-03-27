### Mock Backend

The `MockBackend` provides an in-memory implementation of the `Seetle` trait for testing and development purposes.

#### Features
- **In-Memory Storage**: Keys are stored in memory and are lost when the backend instance is destroyed.
- **Support for ECDSA**: ECDSA P-256 with SHA-256 (using the `ring` crate).
- **Fast and Predictable**: Ideal for unit and integration testing where hardware backends are not available.

#### Usage Example
```rust
use seelte::backends::MockBackend;
use seelte::backends::mock::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let backend = MockBackend::new(storage);

let seetle = backend.seetle();
// Proceed with generating or using keys via the Seetle trait...
```
