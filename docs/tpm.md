### TPM 2.0 Backend

The `TpmBackend` provides hardware-backed key management using Trusted Platform Module (TPM) 2.0. It leverages the `tss-esapi` crate to interact with the TPM.

#### Features

- **Hardware Isolation**: Keys are generated and stored (wrapped) within the TPM.
- **Cryptographic Operations**: Supports digital signatures using ECDSA and RSA (algorithm support depends on the TPM hardware).
- **Persistent Storage**: Uses an external `SecureStorage` to persist key metadata and wrapped key blobs.

#### Requirements

- A TPM 2.0 compliant chip.
- TPM2-TSS software stack (libraries and headers).
- On Linux, the TPM Access Broker & Resource Manager (`tpm2-abrmd`) is recommended.

#### Integration

To enable TPM support, add the `tpm` feature to your `Cargo.toml`:

```toml
[dependencies]
seelte = { version = "0.1.0", features = ["tpm"] }
```

#### Usage

```rust
use seelte::Seelte;
use seelte::backends::tpm::TpmBackend;
use seelte::backends::mock::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let storage = Arc::new(MemoryStorage::new());
    let backend = TpmBackend::new(storage).expect("Failed to initialize TPM backend");
    let seelte = Seelte::new(backend);

    // Use seelte API...
}
```

#### Configuration

The backend uses the standard TPM2-TSS environment variables for configuration (TCTI):

- `TPM2TOOLS_TCTI`: Defines the TCTI to use (e.g., `device:/dev/tpm0`, `tabrmd:`, `mssim:host=localhost,port=2321`).
- `TCTI`: Alternative variable for TCTI configuration.

If no environment variable is set, it defaults to the system default TCTI.
