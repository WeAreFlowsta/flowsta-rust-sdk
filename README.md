# flowsta-rust-sdk

Rust crates for desktop apps that use Flowsta: finding and talking to
Flowsta Vault on the person's own device, signing in with Flowsta, and
keeping an app's device key backed up in the Vault so the same person can
carry on from a new device.

It is the Rust counterpart of [flowsta-sdk](https://github.com/WeAreFlowsta/flowsta-sdk)
(JavaScript), and sits beside [flowsta-hc-lines](https://github.com/WeAreFlowsta/flowsta-hc-lines),
which runs Holochain inside a desktop app.

## What is in it

### `flowsta-vault-client`

No UI framework and no Holochain crates in its dependencies. Every file,
folder and name that is the app's own is passed in.

| Module | What it does |
|---|---|
| `vault` | Finds the person's Flowsta Vault among the ports it can listen on, ignores a Vault that belongs to another user account of the same computer, and prefers the unlocked one. Opens the Vault app when it is installed and not running. |
| `identity` | The link between this install and the person's Flowsta identity, kept on the device, and the two checks a write goes through: everyday writes work with the Vault locked or closed; the few that copy from the live Vault need it open as the same identity. |
| `device_seed` | The seed of the app's device key, kept in a file so a Vault backup can carry it and a new device can carry on as the same key. |
| `adopt` | Replacing the device key in an order that cannot leave it half done, and the check that stops a backup from overwriting a key the person still needs. |
| `profiles` | One profile folder per Flowsta identity, so two people (or one person's two identities) on one install never share keys or data. |

```toml
[dependencies]
flowsta-vault-client = { git = "https://github.com/WeAreFlowsta/flowsta-rust-sdk", rev = "<commit>" }
```

```rust
use flowsta_vault_client::{identity, vault, VaultClient, VaultConfig};

// The origin your webview presents; the Vault knows your app by it.
let vault = VaultClient::new(VaultConfig {
    origin: vault::tauri_origin(tauri::is_dev(), "http://localhost:5173"),
    only_port: None,
})?;

// Is the person's Vault there, and unlocked as whom?
if let Some(found) = vault.find(std::time::Duration::from_secs(2)).await {
    println!("Vault on port {}, unlocked: {}", found.port, found.unlocked);
}

// Before a write: is this install signed in, and is nobody else's Vault open?
match identity::require_identity_link(&vault, &profile_dir).await {
    Ok(link) => { /* write as link.vault_agent_pub_key's install */ }
    Err(why) => { /* say it in your app's words: identity::Refusal */ }
}
```

The sign-in itself (the person approving the link in their Vault) is done
from the webview with [`@flowsta/auth`](https://github.com/WeAreFlowsta/flowsta-sdk);
this crate keeps what that sign-in produced and checks it.

### Not here yet

- The record the sign-in writes on the app's Holochain network, and reading
  which keys belong to one identity. They need the app's own Holochain
  client and stay in the app for now.
- The signed-update check has its own crate,
  [flowsta-update-check](https://github.com/WeAreFlowsta/flowsta-update-check).

## Status

Version 0.1, moved here from ProofPoll, which uses it. The API can still
change before 1.0; pin a commit.

## License

MIT
