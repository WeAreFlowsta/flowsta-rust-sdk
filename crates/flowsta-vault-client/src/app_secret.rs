//! A secret the person's Vault gives this app: the same on every one of
//! their devices, different for every app and every person.
//!
//! Its main use is a private network of the person's own devices. Install
//! a DNA with the secret as its network seed and only that person's
//! devices can ever join it; each device runs its own key there. The Vault
//! derives the secret from the identity, so no device copies it from
//! another and none has to be online for a new one to get it.
//!
//! [`network_secret`] is the call an app makes. It keeps a secret an
//! identity already uses (one kept in a Vault backup by an earlier version
//! of the app, on this device or another) before it asks for the derived
//! one, so a network seed never changes under a person's data.
//!
//! The Vault must be unlocked and the app linked. Nothing is written to
//! the person's history and nothing leaves the device.

use crate::vault::{Refused, VaultClient};
use std::time::Duration;

/// The label used when an app has one private network.
pub const DEFAULT_LABEL: &str = "app-network";

/// Where a [`NetworkSecret`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Read from a Vault backup, this device's or another's: the secret
    /// this identity already uses.
    Existing,
    /// Derived by the Vault from the identity.
    Derived,
}

/// The secret, and where it came from.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkSecret {
    pub secret: [u8; 32],
    pub source: Source,
}

impl NetworkSecret {
    /// The secret as a DNA's `network_seed` takes it.
    pub fn hex(&self) -> String {
        hex::encode(self.secret)
    }
}

// Never printed: a log line or a panic message must not carry it.
impl std::fmt::Debug for NetworkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetworkSecret {{ source: {:?}, secret: <32 bytes> }}", self.source)
    }
}

/// Why no secret came back.
#[derive(Debug, PartialEq, Eq)]
pub enum AppSecretError {
    /// No Vault of this user answered.
    VaultNotFound,
    /// The Vault is locked. Ask the person to unlock it, then call again.
    VaultLocked,
    /// The Vault holds another identity than the one this app is linked to.
    IdentityMismatch,
    /// This app is not linked in the Vault. Sign in with Flowsta first.
    NotLinked,
    /// The Vault refused to say which app the call is from: see [`Refused`].
    Refused(Refused),
    /// The Vault cannot derive a secret for this identity (an identity it
    /// does not host on this device), and no backup carries one.
    NotAvailable,
    /// The label is not 1 to 64 letters, digits, '.', '_' or '-'.
    LabelInvalid,
    /// Anything else, with the Vault's own words.
    Other(String),
}

impl std::fmt::Display for AppSecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppSecretError::VaultNotFound => write!(f, "Flowsta Vault is not running on this device."),
            AppSecretError::VaultLocked => write!(f, "Flowsta Vault is locked. Unlock it and try again."),
            AppSecretError::IdentityMismatch => write!(f, "Flowsta Vault holds a different identity than the one this app is linked to."),
            AppSecretError::NotLinked => write!(f, "This app is not linked in Flowsta Vault. Sign in with Flowsta first."),
            AppSecretError::Refused(r) => write!(f, "{r}"),
            AppSecretError::NotAvailable => write!(f, "Flowsta Vault cannot give this identity an app secret on this device."),
            AppSecretError::LabelInvalid => write!(f, "A label is 1 to 64 letters, digits, '.', '_' or '-'."),
            AppSecretError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AppSecretError {}

/// A label the Vault accepts, checked here so a mistake is caught before a
/// request is made.
pub fn label_ok(label: &str) -> bool {
    (1..=64).contains(&label.len()) && label.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn secret_from_hex(text: &str) -> Option<[u8; 32]> {
    hex::decode(text).ok()?.try_into().ok()
}

/// What a refusal's body means, when it is one this module names.
fn refusal(status: reqwest::StatusCode, body: &serde_json::Value) -> AppSecretError {
    let code = body["error"].as_str().unwrap_or("");
    if let Some(r) = Refused::from_answer(status, body) {
        return AppSecretError::Refused(r);
    }
    match code {
        "vault_locked" | "vault_never_unlocked" => AppSecretError::VaultLocked,
        "identity_mismatch" => AppSecretError::IdentityMismatch,
        "not_linked" => AppSecretError::NotLinked,
        "not_available" => AppSecretError::NotAvailable,
        "label_invalid" => AppSecretError::LabelInvalid,
        _ => AppSecretError::Other(body["description"].as_str().unwrap_or(if code.is_empty() { "the Vault refused the request" } else { code }).to_string()),
    }
}

/// The body of a Vault answer, or `{}` when it is not JSON.
async fn answer(resp: reqwest::Response) -> (reqwest::StatusCode, serde_json::Value) {
    let status = resp.status();
    (status, resp.json::<serde_json::Value>().await.unwrap_or(serde_json::Value::Null))
}

/// The secret the Vault derives for this app and `label`. The same on
/// every device of the identity, at once: nothing is copied or waited for.
///
/// An app with one private network calls [`network_secret`] instead, which
/// also honors a secret the identity already uses.
pub async fn derived(vault: &VaultClient, label: &str) -> Result<[u8; 32], AppSecretError> {
    if !label_ok(label) {
        return Err(AppSecretError::LabelInvalid);
    }
    let url = format!("{}/app-secret", vault.base_url().await);
    let resp = vault
        .post(&url, serde_json::json!({ "label": label }))
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|_| AppSecretError::VaultNotFound)?;
    let (status, body) = answer(resp).await;
    if !status.is_success() {
        // A Vault from before the route answers 404.
        return Err(if status == reqwest::StatusCode::NOT_FOUND { AppSecretError::NotAvailable } else { refusal(status, &body) });
    }
    body["secret_hex"].as_str().and_then(secret_from_hex).ok_or_else(|| AppSecretError::Other("the Vault's answer held no 32-byte secret".into()))
}

/// The secret a Vault backup carries under `label`, on this device or
/// (with `across_devices`) on any other device of the identity. `None`
/// when there is none.
async fn kept(vault: &VaultClient, client_id: &str, label: &str, across_devices: bool) -> Result<Option<[u8; 32]>, AppSecretError> {
    let url = format!("{}/backup/retrieve", vault.base_url().await);
    let mut body = serde_json::json!({ "client_id": client_id, "label": label });
    if across_devices {
        body["across"] = "devices".into();
    }
    let resp = vault.post(&url, body).timeout(Duration::from_secs(30)).send().await.map_err(|_| AppSecretError::VaultNotFound)?;
    let (status, body) = answer(resp).await;
    if status == reqwest::StatusCode::NOT_FOUND || body["error"] == "backup_not_found" {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(if status == reqwest::StatusCode::CONFLICT { AppSecretError::IdentityMismatch } else { refusal(status, &body) });
    }
    Ok(body["data"]["secret_hex"].as_str().and_then(secret_from_hex))
}

/// One private-network secret per identity per app: use it as the network
/// seed of a DNA that only the person's own devices join.
///
/// The order, so a secret never changes once an identity has one: a Vault
/// backup under `label` on this device, then on any other device, then the
/// secret the Vault derives. A derived secret is also written to this
/// device's backup under `label`, so a later read finds the same one
/// whatever changes.
///
/// `app_name` is the name the backup is kept under in the person's Vault.
/// The client must have been made with its `client_id`.
pub async fn network_secret(vault: &VaultClient, app_name: &str, label: &str) -> Result<NetworkSecret, AppSecretError> {
    if !label_ok(label) {
        return Err(AppSecretError::LabelInvalid);
    }
    let client_id = vault.client_id().ok_or_else(|| AppSecretError::Other("the Vault client was made without the app's client id".into()))?.to_string();
    if let Some(secret) = kept(vault, &client_id, label, false).await? {
        return Ok(NetworkSecret { secret, source: Source::Existing });
    }
    if let Some(secret) = kept(vault, &client_id, label, true).await? {
        return Ok(NetworkSecret { secret, source: Source::Existing });
    }
    let secret = derived(vault, label).await?;
    // Kept as a courtesy to later reads: the secret is already in hand, so
    // a refused or failed write changes nothing.
    let url = format!("{}/backup", vault.base_url().await);
    let write = serde_json::json!({
        "client_id": client_id,
        "app_name": app_name,
        "label": label,
        "data": { "secret_hex": hex::encode(secret), "source": "derived" },
    });
    let _ = vault.post(&url, write).timeout(Duration::from_secs(30)).send().await;
    Ok(NetworkSecret { secret, source: Source::Derived })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{test_vault, VaultConfig};
    use serde_json::json;

    const A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn client_for(vault: &test_vault::TestVault) -> VaultClient {
        VaultClient::new(VaultConfig { origin: "testapp://app".into(), only_port: Some(vault.port), client_id: Some("flowsta_app_1".into()) }).unwrap()
    }

    /// `/status` as an unlocked Vault of this user answers it; anything
    /// else goes to `other`.
    fn vault_with(other: impl Fn(&test_vault::Seen) -> (u16, serde_json::Value) + Send + 'static) -> test_vault::TestVault {
        test_vault::start(move |seen| {
            if seen.path() == "/status" {
                (200, json!({ "running": true, "unlocked": true, "initialized": true, "agent_pub_key": "uhCAkAda" }))
            } else {
                other(seen)
            }
        })
    }

    fn calls(vault: &test_vault::TestVault) -> Vec<String> {
        vault
            .seen()
            .iter()
            .filter(|s| s.path() != "/status")
            .map(|s| format!("{}{}", s.path(), if s.body["across"] == "devices" { ":devices" } else { "" }))
            .collect()
    }

    #[tokio::test]
    async fn a_secret_this_devices_backup_carries_is_kept_before_anything_else() {
        let vault = vault_with(|_| (200, json!({ "data": { "secret_hex": A }, "label": "app-network" })));
        let got = network_secret(&client_for(&vault), "Test App", DEFAULT_LABEL).await.unwrap();
        assert_eq!((got.hex().as_str(), got.source), (A, Source::Existing));
        assert_eq!(calls(&vault), ["/backup/retrieve"], "nothing derived, nothing written");
    }

    #[tokio::test]
    async fn another_devices_copy_is_taken_before_deriving() {
        let vault = vault_with(|seen| {
            if seen.body["across"] == "devices" {
                (200, json!({ "data": { "secret_hex": B }, "from_device": "dev-b" }))
            } else {
                (404, json!({ "error": "backup_not_found" }))
            }
        });
        let got = network_secret(&client_for(&vault), "Test App", DEFAULT_LABEL).await.unwrap();
        assert_eq!((got.hex().as_str(), got.source), (B, Source::Existing));
        assert_eq!(calls(&vault), ["/backup/retrieve", "/backup/retrieve:devices"]);
    }

    #[tokio::test]
    async fn with_no_backup_the_vault_derives_it_and_the_secret_is_kept_in_this_devices_backup() {
        let vault = vault_with(|seen| match seen.path() {
            "/backup/retrieve" => (404, json!({ "error": "backup_not_found" })),
            "/app-secret" => (200, json!({ "success": true, "label": "app-network", "secret_hex": A })),
            _ => (200, json!({ "success": true })),
        });
        let client = client_for(&vault);
        client.set_link_token(Some("tok-1".into()));
        let got = network_secret(&client, "Test App", DEFAULT_LABEL).await.unwrap();
        assert_eq!((got.hex().as_str(), got.source), (A, Source::Derived));
        assert_eq!(calls(&vault), ["/backup/retrieve", "/backup/retrieve:devices", "/app-secret", "/backup"]);

        let asked = &vault.seen_on("/app-secret")[0];
        assert_eq!(asked.body, json!({ "label": "app-network", "link_token": "tok-1", "client_id": "flowsta_app_1" }), "the call says which app it is from");
        let written = &vault.seen_on("/backup")[0];
        assert_eq!(written.body["data"], json!({ "secret_hex": A, "source": "derived" }));
        assert_eq!((written.body["app_name"].as_str(), written.body["label"].as_str()), (Some("Test App"), Some("app-network")));
    }

    #[tokio::test]
    async fn a_backup_write_that_fails_does_not_lose_the_secret() {
        let vault = vault_with(|seen| match seen.path() {
            "/backup/retrieve" => (404, json!({ "error": "backup_not_found" })),
            "/app-secret" => (200, json!({ "secret_hex": A })),
            _ => (403, json!({ "error": "vault_locked" })),
        });
        let got = network_secret(&client_for(&vault), "Test App", DEFAULT_LABEL).await.unwrap();
        assert_eq!(got.source, Source::Derived);
    }

    #[tokio::test]
    async fn each_refusal_is_named() {
        for (status, code, want) in [
            (403, "vault_locked", AppSecretError::VaultLocked),
            (403, "vault_never_unlocked", AppSecretError::VaultLocked),
            (403, "not_linked", AppSecretError::NotLinked),
            (409, "not_available", AppSecretError::NotAvailable),
            (409, "identity_mismatch", AppSecretError::IdentityMismatch),
            (403, "invalid_link_token", AppSecretError::Refused(Refused::InvalidLinkToken)),
            (404, "", AppSecretError::NotAvailable),
        ] {
            let vault = vault_with(move |_| (status, json!({ "error": code })));
            assert_eq!(derived(&client_for(&vault), "app-network").await.unwrap_err(), want, "{status} {code}");
        }
        let locked = vault_with(|_| (403, json!({ "error": "vault_locked" })));
        assert_eq!(network_secret(&client_for(&locked), "Test App", DEFAULT_LABEL).await.unwrap_err(), AppSecretError::VaultLocked, "a locked Vault is said so, not read as no backup");
    }

    #[tokio::test]
    async fn a_bad_label_or_a_client_with_no_client_id_asks_the_vault_nothing() {
        let vault = vault_with(|_| (200, json!({ "secret_hex": A })));
        let client = client_for(&vault);
        for label in ["", "has space", "slash/label", &"x".repeat(65)] {
            assert_eq!(derived(&client, label).await.unwrap_err(), AppSecretError::LabelInvalid, "{label:?}");
            assert_eq!(network_secret(&client, "Test App", label).await.unwrap_err(), AppSecretError::LabelInvalid);
        }
        let unnamed = VaultClient::new(VaultConfig { origin: "testapp://app".into(), only_port: Some(vault.port), client_id: None }).unwrap();
        assert!(matches!(network_secret(&unnamed, "Test App", DEFAULT_LABEL).await, Err(AppSecretError::Other(_))));
        assert!(calls(&vault).is_empty(), "{:?}", calls(&vault));
    }

    #[test]
    fn the_secret_is_never_printed() {
        let s = NetworkSecret { secret: [7; 32], source: Source::Derived };
        let shown = format!("{s:?}");
        assert!(!shown.contains("0707") && !shown.contains("7, 7"), "{shown}");
    }

    #[tokio::test]
    async fn an_answer_with_no_usable_secret_is_an_error_not_a_secret() {
        let vault = vault_with(|_| (200, json!({ "secret_hex": "abcd" })));
        assert!(matches!(derived(&client_for(&vault), "app-network").await, Err(AppSecretError::Other(_))));
    }
}
