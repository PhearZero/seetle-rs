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
use seelte::backends::xhd::XHDBackend;
use seelte::storage::MemoryStorage;
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
use seelte::{Algorithm, Bindings, KeyUsage};

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

#### Internal Metadata

The backend stores the derivation parameters in the provided `SecureStorage` under the key's identifier. This allows the backend to re-derive the private key when needed for signing without storing the private key material itself in the storage. Only the root `XPrv` needs to be securely managed by the application.

#### Enhancing Metadata Security with TPM

To add hardware protection to the derivation parameters, you can wrap your storage with `TpmStorage`:

```rust
use seelte::storage::{MemoryStorage, TpmStorage};
use seelte::backends::xhd::XHDBackend;
use xhd_wallet_api::XPrv;
use std::sync::Arc;

let base_storage = Arc::new(MemoryStorage::new());
let secure_storage = Arc::new(TpmStorage::new(base_storage).unwrap());

let root_key = XPrv::from_seed(&[0u8; 64]);
let backend = XHDBackend::new(secure_storage, root_key);
```
