### TPM 2.0 Backend

The `TpmBackend` provides hardware-backed key management using Trusted Platform Module (TPM) 2.0. It leverages the `tss-esapi` crate to interact with the TPM.

#### Features

- **Hardware Isolation**: Keys are generated and stored (wrapped) within the TPM.
- **Cryptographic Operations**: Supports digital signatures using ECDSA, Ed25519, and RSA (algorithm support depends on the TPM hardware).
- **Persistent Storage**: Uses an external `SecureStorage` to persist key metadata and wrapped key blobs.

#### Requirements (Linux)

To use the TPM 2.0 backend, the following system dependencies are required:

- **Hardware**: A TPM 2.0 compliant chip (Discrete or Firmware).
- **Libraries**: TPM2-TSS software stack and CLI tools.
  - Ubuntu/Debian: `sudo apt install libtss2-dev tpm2-tools`
  - Fedora: `sudo dnf install tpm2-tss-devel tpm2-tools`
- **Access**: Your user must have permission to access `/dev/tpmrm0`. This is usually handled by adding your user to the `tss` group:
  ```bash
  sudo usermod -aG tss $USER
  ```
  *Logout and login for changes to take effect.*

- **Resource Manager**: It's highly recommended to use the TPM Access Broker & Resource Manager (`tpm2-abrmd`) to avoid session exhaustion and permit multiple concurrent users of the TPM.

#### Installation (tpm2-abrmd)

If you are using a shared system or multiple processes need to access the TPM at the same time, install and run `tpm2-abrmd`:

- Ubuntu/Debian: `sudo apt install tpm2-abrmd`
- Fedora: `sudo dnf install tpm2-abrmd`
- Arch: `sudo pacman -S tpm2-abrmd`

Once installed, the library will automatically attempt to connect via D-Bus (using the `tabrmd:` TCTI). This is the most robust and recommended way for non-root users to access the TPM.

#### Troubleshooting Permissions

If you encounter permission errors like "failed to open TPM device" (Permission denied), follow these steps:

1. **Check device ownership**:
   ```bash
   ls -l /dev/tpmrm0
   ```
   It should be owned by `tss:tss`.

2. **Verify group membership**:
   ```bash
   id
   ```
   Ensure `tss` is listed in your groups.

3. **Try the Access Broker**:
   If you have `tpm2-abrmd` running, ensure your user can access the D-Bus interface. On most systems, this is allowed by default for users in the `tss` group.

4. **Direct Device Access (Not Recommended for Multi-user)**:
   If you must use direct access, ensure your user is in the `tss` group. If the device exists but you still get "Permission denied", double-check your group memberships and logout/login.

#### TCTI Configuration

The backend uses the standard TPM2-TSS environment variables for configuration (TCTI). If no TCTI is specified, it will attempt to use the default (usually `/dev/tpmrm0` if available).

- `TPM2TOOLS_TCTI`: Defines the TCTI to use (e.g., `device:/dev/tpmrm0`, `tabrmd:`, `mssim:host=localhost,port=2321`).
- `TCTI`: Alternative variable for TCTI configuration.

To enable TPM support, add the `tpm` feature to your `Cargo.toml`:

```toml
[dependencies]
seetle = { version = "0.1.0", features = ["tpm"] }
```

#### Usage

```rust
use seetle::Seetle;
use seetle::tpm::TpmBackend;
use seetle::memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let storage = Arc::new(MemoryStorage::new());
    
    // 1. Create a TPM context
    let tpm_context = TpmBackend::create_context(None).expect("Failed to create TPM context");
    
    // 2. Initialize TPM backend with the context
    let backend = TpmBackend::new(storage, tpm_context).expect("Failed to initialize TPM backend");
    let seetle = Seetle::new(backend);

    // Use seetle API...
}
```

#### Configuration

The backend uses the standard TPM2-TSS environment variables for configuration (TCTI):

- `TPM2TOOLS_TCTI`: Defines the TCTI to use (e.g., `device:/dev/tpmrm0`, `tabrmd:`, `mssim:host=localhost,port=2321`).
- `TCTI`: Alternative variable for TCTI configuration.

If you encounter permission errors like "failed to open TPM device", ensure you are using `/dev/tpmrm0` (the resource manager) and not `/dev/tpm0` directly, and that your user has the necessary permissions.


#### TPM-Backed Storage (TpmStorage)

In addition to `TpmBackend`, the library provides `TpmStorage`, a decorator that can wrap any `SecureStorage` implementation. It uses the TPM to encrypt (wrap) any data stored in it, such as derivation paths or other sensitive metadata from other backends.

```rust
use seetle::memory::MemoryStorage;
use seetle::tpm::{TpmBackend, TpmStorage};
use seetle::xhd::XHDBackend;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());

// 1. Create a shared TPM context
let tpm_context = TpmBackend::create_context(None).expect("Failed to create TPM context");

// 2. Wrap the base storage using the TPM context
let secure_storage = Arc::new(TpmStorage::new(base_storage, tpm_context).unwrap());

let root_key = XPrv::from_seed(&[0u8; 64]);
let xhd_backend = XHDBackend::new(secure_storage, root_key);
```

This ensures that even if the base storage (e.g., a file or a database) is compromised, the sensitive metadata is protected by the hardware TPM.
