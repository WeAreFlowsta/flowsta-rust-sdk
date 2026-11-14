//! The link between this install and the person's Flowsta identity, kept
//! on this device, and the two checks every write goes through.
//!
//! Two files in the profile's folder work together:
//!   - `identity-link.json`: the Vault's agent key and the hash of the link
//!     record (the person signed in with Flowsta here; it survives a move
//!     to a new network);
//!   - `profile-cache.json`: the display name and picture, so the app can
//!     show who is signed in while the Vault is closed or locked.
//!
//! The Vault is needed for the sign-in itself. After it, everyday actions
//! go ahead with the Vault locked or closed ([`require_identity_link`]);
//! the few that copy from the live Vault or rebind to it need it open as
//! the same identity ([`require_identity_match`]).

use crate::vault::VaultClient;
use std::path::{Path, PathBuf};

pub const IDENTITY_LINK_FILE: &str = "identity-link.json";
pub const PROFILE_CACHE_FILE: &str = "profile-cache.json";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct IdentityLinkData {
    pub vault_agent_pub_key: String,
    pub entry_action_hash: String,
    pub linked_at: i64,
}

pub fn identity_link_path(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_LINK_FILE)
}

pub fn load_identity_link(data_dir: &Path) -> Option<IdentityLinkData> {
    let json = std::fs::read_to_string(identity_link_path(data_dir)).ok()?;
    serde_json::from_str(&json).ok()
}

pub fn save_identity_link(data_dir: &Path, data: &IdentityLinkData) {
    if let Ok(json) = serde_json::to_string_pretty(data) {
        let _ = std::fs::write(identity_link_path(data_dir), json);
    }
}

pub fn delete_identity_link(data_dir: &Path) {
    let _ = std::fs::remove_file(identity_link_path(data_dir));
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct CachedProfile {
    pub display_name: Option<String>,
    pub profile_picture: Option<String>,
}

pub fn profile_cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PROFILE_CACHE_FILE)
}

pub fn load_cached_profile(data_dir: &Path) -> Option<CachedProfile> {
    let json = std::fs::read_to_string(profile_cache_path(data_dir)).ok()?;
    serde_json::from_str(&json).ok()
}

pub fn save_cached_profile(data_dir: &Path, profile: &CachedProfile) {
    if let Ok(json) = serde_json::to_string_pretty(profile) {
        let _ = std::fs::write(profile_cache_path(data_dir), json);
    }
}

pub fn delete_cached_profile(data_dir: &Path) {
    let _ = std::fs::remove_file(profile_cache_path(data_dir));
}

/// Why a write was refused. The app says it in its own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No identity link on this device: sign in first.
    NotLinked,
    /// No Vault of this person's answered, so it cannot be confirmed that
    /// it is them.
    VaultNotRunning,
    /// The Vault is locked.
    VaultLocked,
    /// The Vault is unlocked as a different identity than the one signed
    /// in here.
    OtherIdentity,
}

/// What a Vault said: whether it is unlocked, and as which identity.
pub type Live = Option<(bool, Option<String>)>;

/// The decision of [`require_identity_match`], given what is on disk and
/// what the Vault said. Both keys come from the Vault's own spelling, so
/// plain string equality is exact.
pub fn match_decision(link: Option<IdentityLinkData>, live: Live) -> Result<IdentityLinkData, Refusal> {
    let link = link.ok_or(Refusal::NotLinked)?;
    let (unlocked, live) = live.ok_or(Refusal::VaultNotRunning)?;
    if !unlocked {
        return Err(Refusal::VaultLocked);
    }
    match live {
        Some(ref key) if *key == link.vault_agent_pub_key => Ok(link),
        Some(_) => Err(Refusal::OtherIdentity),
        None => Err(Refusal::VaultLocked),
    }
}

/// The decision of [`require_identity_link`].
pub fn link_decision(link: Option<IdentityLinkData>, live: Live) -> Result<IdentityLinkData, Refusal> {
    let link = link.ok_or(Refusal::NotLinked)?;
    if let Some((true, Some(ref key))) = live {
        if *key != link.vault_agent_pub_key {
            return Err(Refusal::OtherIdentity);
        }
    }
    Ok(link)
}

/// For operations that copy from the live Vault or rebind to it (refreshing
/// the cached profile, adopting or replacing the device key): the install
/// must be signed in AND the Vault must be reachable, unlocked and the same
/// identity. A Vault that does not answer in time refuses.
pub async fn require_identity_match(vault: &VaultClient, data_dir: &Path) -> Result<IdentityLinkData, Refusal> {
    let link = load_identity_link(data_dir).ok_or(Refusal::NotLinked)?;
    match_decision(Some(link), vault.live_identity().await)
}

/// For everyday writes: the install must be signed in, but the Vault does
/// not have to be running or unlocked (a locked Vault on the person's own
/// device is the normal resting state). The one refusal beyond "not signed
/// in" is a DIFFERENT identity unlocked on this device: nothing is written
/// under this install's key while someone else's Vault is open.
pub async fn require_identity_link(vault: &VaultClient, data_dir: &Path) -> Result<IdentityLinkData, Refusal> {
    let link = load_identity_link(data_dir).ok_or(Refusal::NotLinked)?;
    link_decision(Some(link), vault.live_identity().await)
}

/// The 39 bytes of an agent key written `uhCAk...`: the base64url body
/// decoded and kept whole (prefix, key, location), so the key matches what
/// the other side signed.
pub fn parse_agent_key(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let b64 = s.strip_prefix('u').ok_or("Agent key must start with 'u'")?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).map_err(|e| format!("Invalid base64 in agent key: {}", e))?;
    if raw.len() != 39 {
        return Err(format!("Agent key wrong length: {} (expected 39)", raw.len()));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(key: &str) -> Option<IdentityLinkData> {
        Some(IdentityLinkData { vault_agent_pub_key: key.into(), entry_action_hash: "uhCkk".into(), linked_at: 1 })
    }

    #[test]
    fn everyday_writes_need_a_link_and_refuse_only_another_identity_unlocked() {
        assert_eq!(link_decision(None, Some((true, Some("A".into())))), Err(Refusal::NotLinked));
        assert!(link_decision(link("A"), None).is_ok(), "no Vault running: allowed");
        assert!(link_decision(link("A"), Some((false, Some("B".into())))).is_ok(), "another identity, locked: allowed");
        assert!(link_decision(link("A"), Some((true, None))).is_ok());
        assert!(link_decision(link("A"), Some((true, Some("A".into())))).is_ok());
        assert_eq!(link_decision(link("A"), Some((true, Some("B".into())))), Err(Refusal::OtherIdentity));
    }

    #[test]
    fn operations_on_the_live_vault_need_it_open_as_the_same_identity() {
        assert_eq!(match_decision(None, Some((true, Some("A".into())))), Err(Refusal::NotLinked));
        assert_eq!(match_decision(link("A"), None), Err(Refusal::VaultNotRunning));
        assert_eq!(match_decision(link("A"), Some((false, Some("A".into())))), Err(Refusal::VaultLocked));
        assert_eq!(match_decision(link("A"), Some((true, None))), Err(Refusal::VaultLocked));
        assert_eq!(match_decision(link("A"), Some((true, Some("B".into())))), Err(Refusal::OtherIdentity));
        assert_eq!(match_decision(link("A"), Some((true, Some("A".into())))).unwrap().vault_agent_pub_key, "A");
    }

    #[test]
    fn the_link_and_the_cached_profile_round_trip_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_identity_link(dir.path()).is_none());
        let l = link("uhCAkA").unwrap();
        save_identity_link(dir.path(), &l);
        assert_eq!(load_identity_link(dir.path()), Some(l));
        let p = CachedProfile { display_name: Some("Ada".into()), profile_picture: None };
        save_cached_profile(dir.path(), &p);
        assert_eq!(load_cached_profile(dir.path()), Some(p));
        delete_identity_link(dir.path());
        delete_cached_profile(dir.path());
        assert!(load_identity_link(dir.path()).is_none() && load_cached_profile(dir.path()).is_none());
    }

    #[test]
    fn an_agent_key_is_39_bytes_behind_a_u() {
        use base64::Engine;
        let raw: Vec<u8> = [0x84u8, 0x20, 0x24].into_iter().chain((0..36).map(|i| i as u8)).collect();
        let s = format!("u{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw));
        assert_eq!(parse_agent_key(&s).unwrap(), raw);
        assert!(parse_agent_key(&s[1..]).is_err());
        assert!(parse_agent_key("uAAAA").is_err());
    }
}
