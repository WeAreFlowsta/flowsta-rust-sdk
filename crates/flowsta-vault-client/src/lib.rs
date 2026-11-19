//! The Flowsta side of a desktop app: find and talk to Flowsta Vault on
//! the person's own device, keep the link between this install and their
//! identity, keep the app's device key where a Vault backup can carry it,
//! and keep one profile per identity.
//!
//! Nothing here depends on a UI framework or on Holochain's crates, and
//! every file, folder and name that is the app's own is passed in.
//!
//! - [`vault`]: which Vault to talk to, and whose it is.
//! - [`identity`]: the identity link on this device and the two checks
//!   every write goes through.
//! - [`device_seed`]: the device key's seed file.
//! - [`adopt`]: replacing the device key in a safe order, and the check
//!   that keeps a backup from overwriting a key still needed.
//! - [`profiles`]: one profile folder per identity.
//! - [`app_secret`]: a secret that is the same on every one of the
//!   person's devices, for a private network of their own devices.

pub mod adopt;
pub mod app_secret;
pub mod device_seed;
pub mod identity;
pub mod profiles;
pub mod vault;

pub use vault::{VaultClient, VaultConfig, VaultProbe};
