### XHD Backend

The `XHDBackend` provides support for Hierarchical Deterministic (HD) wallets using the `xhd-wallet-api` crate. It allows deriving Ed25519 keys from a root extended private key (XPrv) using BIP44-style paths.

#### Features

- **BIP32-style Ed25519 key derivation**: Efficiently derive multiple keys from a single root secret.
- **Multiple Derivation Schemes**: Support for `Peikert` and `V2` (Khovratovich) schemes.
- **Context-Aware Derivation**: Separate contexts for Algorand (Address) and Identity keys.
- **Hardware-Independent**: Perform HD derivation on any platform supported by Rust.
- **Secure Metadata Storage**: Derivation parameters are stored in `SecureStorage`, while the private key material is derived on-the-fly.

#### Prerequisites

- **Git**: Required for fetching the `xhd-wallet-api` dependency.

#### Build Configuration

To use the `XHDBackend`, ensure your `Cargo.toml` includes the `xhd-wallet-api` dependency:

```toml
[dependencies]
xhd-wallet-api = { package = "ed25519-bip32", git = "https://github.com/algorandfoundation/xHD-Wallet-API-rs.git" }
```

#### Usage Example

To use the `XHDBackend`, you need to provide a root extended private key (XPrv) and a `SecureStorage` implementation.

```rust
use seetle::xhd::XHDBackend;
use seetle::memory::MemoryStorage;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
let root_key = XPrv::from_seed(&[0u8; 64]); // Example seed
let backend = XHDBackend::new(storage, root_key);

let seetle = backend.seetle();
```

##### Generating a Derived Key

When generating a key, specify derivation parameters in the algorithm name using the format `XHD:<Context>:<Account>:<Index>:<Scheme>`.

- **Context**: `Address` or `Identity`.
- **Account**: Account index (u32).
- **Index**: Key index (u32).
- **Scheme**: `Peikert` or `V2`.

```rust
use seetle::{Algorithm, Bindings, KeyUsage};

let algorithm = Algorithm::Ed25519 {
    name: "XHD:Address:0:0:Peikert".into(),
};

let bindings = Bindings {
    identifier: "my-derived-key".into(),
    ..Default::default()
};

let key_id = seetle.generate_key(
    algorithm,
    false,
    Some(bindings),
    vec![KeyUsage::Sign, KeyUsage::Verify]
).await.unwrap();
```

##### Signing and Verifying

Once a key is generated (derived), it can be used for signing and verification by its identifier.

```rust
let data = b"Hello, world!";
let signature = seetle.sign(
    Algorithm::Generic { name: "ignored".into() },
    key_id.clone(),
    data.to_vec()
).await.unwrap();

let valid = seetle.verify(
    Algorithm::Generic { name: "ignored".into() },
    key_id,
    signature,
    data.to_vec()
).await.unwrap();

assert!(valid);
```

#### Hardware-Backed Root Keys

For enhanced security, the `XHDBackend` can use another `Seetle` backend to provide its root key material (seed). This allows the master seed of your HD wallet to be hardware-bound (e.g., inside a TPM or Secure Enclave).

The backend will attempt to use `derive_bits` on the root provider backend to obtain a 512-bit (64-byte) seed. If `derive_bits` is not supported, it will fall back to `export_key`.

##### TPM Example

```rust
use seetle::xhd::XHDBackend;
use seetle::tpm::TpmBackend;
use seetle::memory::MemoryStorage;
use seetle::{Algorithm, Bindings, KeyUsage};
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());

// 1. Initialize the root provider (e.g. TPM)
let tpm_storage = Arc::new(MemoryStorage::new());
let tpm_backend = Arc::new(TpmBackend::new(tpm_storage).unwrap());
let tpm_seetle: Arc<dyn Seetle> = tpm_backend;

// 2. Generate a master key in the TPM
let master_key_id = tpm_seetle.generate_key(
    Algorithm::Generic { name: "MasterKey".into() },
    false,
    Some(Bindings { identifier: "xhd-master".into(), ..Default::default() }),
    vec![KeyUsage::DeriveBits]
).await.unwrap();

// 3. Initialize XHDBackend using the TPM key as the root
let xhd_backend = XHDBackend::new_with_backend(
    storage,
    tpm_seetle,
    "xhd-master".into(),
    Algorithm::Generic { name: "MasterKey".into() }
);
```

##### Nordic Example

```rust
use seetle::xhd::XHDBackend;
use seetle::nordic::NordicBackend;
use seetle::memory::MemoryStorage;
use seetle::{Algorithm, Bindings, KeyUsage, Seetle};
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());

// 1. Initialize Nordic Backend
let nordic_storage = Arc::new(MemoryStorage::new());
let nordic_backend = Arc::new(NordicBackend::new(nordic_storage));
nordic_backend.init().unwrap(); // Initialize PSA subsystem

// 2. Generate a master seed in the Nordic hardware
let master_key_id = nordic_backend.generate_key(
    Algorithm::Raw { length: 512 },
    false,
    Some(Bindings { identifier: "xhd-master".into(), ..Default::default() }),
    vec![KeyUsage::DeriveBits]
).await.unwrap();

// 3. Initialize XHDBackend using the Nordic key as the root
let xhd_backend = XHDBackend::new_with_backend(
    storage,
    nordic_backend.clone(),
    "xhd-master".into(),
    Algorithm::Raw { length: 512 }
);
```

#### Key Metadata

When retrieving metadata for an xHD key using `get_key_metadata`, the following xHD-specific fields are provided:

- **Context**: `Address` or `Identity`.
- **Account**: The BIP44-style account index.
- **Index**: The BIP44-style key index.
- **Derivation**: The derivation scheme used (`Peikert` or `V2`).
- **Master Seed**: The identifier of the root key in the provider backend (or `Direct` if provided in memory).
- **Seed Export**: Whether the root master seed can be exported from its provider backend.

#### Internal Metadata

The backend stores the derivation parameters in the provided `SecureStorage` under the key's identifier. This allows the backend to re-derive the private key when needed for signing without storing the private key material itself in the storage. Only the root `XPrv` needs to be securely managed by the application.

#### Enhancing Metadata Security with TPM

To add hardware protection to the derivation parameters, you can wrap your storage with `TpmStorage`:

```rust
use seetle::memory::MemoryStorage;
use seetle::tpm::TpmStorage;
use seetle::xhd::XHDBackend;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let secure_storage = Arc::new(TpmStorage::new(base_storage).unwrap());

let root_key = XPrv::from_seed(&[0u8; 64]);
let backend = XHDBackend::new(secure_storage, root_key);
```
