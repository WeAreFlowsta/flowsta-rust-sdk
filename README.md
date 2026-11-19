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
| `vault` | Finds the person's Flowsta Vault among the ports it can listen on, ignores a Vault that belongs to another user account of the same computer, and prefers the unlocked one. Says which app each call is from (its origin, client id and link token). Opens the Vault app when it is installed and not running. |
| `identity` | The link between this install and the person's Flowsta identity, kept on the device, and the two checks a write goes through: everyday writes work with the Vault locked or closed; the few that copy from the live Vault need it open as the same identity. |
| `device_seed` | The seed of the app's device key, kept in a file so a Vault backup can carry it and a new device can carry on as the same key. |
| `adopt` | Replacing the device key in an order that cannot leave it half done, and the check that stops a backup from overwriting a key the person still needs. |
| `profiles` | One profile folder per Flowsta identity, so two people (or one person's two identities) on one install never share keys or data. |
| `app_secret` | A secret the Vault gives this app that is the same on every one of the person's devices and different for every app and every person. Used as a DNA's network seed, it makes a private network that only that person's devices join. |

```toml
[dependencies]
flowsta-vault-client = { git = "https://github.com/WeAreFlowsta/flowsta-rust-sdk", rev = "<commit>" }
```

```rust
use flowsta_vault_client::{identity, vault, VaultClient, VaultConfig};

// An origin of your app's own, and its Flowsta client id.
let vault = VaultClient::new(VaultConfig {
    origin: "yourapp://app".into(),
    only_port: None,
    client_id: Some("your_client_id".into()),
})?;

// The link token the Vault gave when the person linked your app. Your app
// keeps it in its own storage and sets it at each start, and again after
// each sign-in; `None` forgets it.
vault.set_link_token(stored_link_token);

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
from the webview with `linkFlowstaIdentity` from
[`@flowsta/holochain`](https://github.com/WeAreFlowsta/flowsta-sdk);
this crate keeps what that sign-in produced and checks it.

How-tos for each module: [docs.flowsta.com/sdk/vault-client](https://docs.flowsta.com/sdk/vault-client).

### Which app a call is from

The Vault tells apps apart by three things a call presents:

- **The origin.** The Vault records the origin a link was made from. Calls
  made from Rust should present an origin of the app's own, for example
  `yourapp://app`.
- **The link token.** The Vault gives one in its answer when the person
  links the app (`link_token`), and from then on it names that one link,
  whatever else presents the same origin. It is accepted only from the
  origin the link was made from. Hand it to `set_link_token`; clones of
  the client share it.
- **The client id.** Without a token, it picks your app among several that
  present one origin.

`vault.get(url)` and `vault.post(url, body)` add the token and the client
id to a call when they are known: query parameters on a GET, fields of the
JSON body on a POST. `find`, `live_identity` and the backup read in `adopt`
go through them. A Vault from before link tokens ignores both, so nothing
changes there. `vault.http()` is the plain client, with the origin only.

**When the link is made from the webview** (the usual case with
`@flowsta/holochain`), the Vault recorded the webview's origin, and a token made
there is accepted only from that origin. The Rust side then has to present
the same origin as the webview: that is what `vault::tauri_origin` is for.

```rust
let vault = VaultClient::new(VaultConfig {
    origin: vault::tauri_origin(tauri::is_dev(), "http://localhost:5173"),
    only_port: None,
    client_id: Some("your_client_id".into()),
})?;
```

Every Tauri app's webview presents that same origin, so an app that uses it
should always set its client id and its link token.

When the Vault refuses a call because of who it is from, its answer is a
403 with an `error` code that `vault::Refused` reads: `invalid_link_token`
(the link is gone or was made again: forget the token and sign in again),
`link_token_required`, `app_ambiguous` (send the client id),
`origin_not_registered` and `not_addressed_here`.

### A private network of the person's own devices

```rust
use flowsta_vault_client::app_secret::{network_secret, DEFAULT_LABEL};

let secret = network_secret(&vault, "My App", DEFAULT_LABEL).await?;
// install the private DNA with `secret.hex()` as its network seed
```

The Vault derives the secret from the person's identity, so every device
they sign in on gets the same one with nothing copied between devices.
Give each device its own key on that network. The Vault must be unlocked
and the app linked; `AppSecretError` names each reason it can refuse
(`VaultLocked`, `NotLinked`, `IdentityMismatch`, ...). A secret an identity
already uses, kept in a Vault backup under the same label, is returned in
preference, so the network seed never changes under a person's data.
`app_secret::derived` is the plain call for any other label, for example a
data key.

### Not here yet

- The record the sign-in writes on the app's Holochain network, and reading
  which keys belong to one identity. They need the app's own Holochain
  client and stay in the app for now.
- The signed-update check has its own crate,
  [flowsta-update-check](https://github.com/WeAreFlowsta/flowsta-update-check).

## Status

Version 0.2.2. The API can still change before 1.0; pin a commit.

Since 0.1: `VaultConfig` has a new field, `client_id` (add
`client_id: None` to keep an app as it was); `VaultClient` carries a link
token (`set_link_token`, `link_token`) and has `get` and `post`, which say
which app a call is from; `vault::Refused` names the Vault's refusals about
that.

0.2.1 adds `profiles::select_unbound_profile_root`: the profile to open when
the person asks for the app as an identity the Vault holds and does not
name yet (it names its identity only to an app connected under it).

0.2.2 adds `app_secret`: the Vault's per-app secret (`network_secret`,
`derived`), for a private network of the person's own devices.

## License

MIT
