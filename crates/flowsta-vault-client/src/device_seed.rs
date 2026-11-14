//! The device key's seed: made by the app, kept in a file of the app's
//! naming, and carried in the person's Vault backup.
//!
//! The seed is created here (not inside the key store) so the backup can
//! carry it: the backup then holds the means of authorship, and a restore
//! imports the same seed, the same key, on a new device. The key store
//! still holds and uses the seed for signing; this module is its origin and
//! its recovery copy, under the same custody as the key store's own files.
//!
//! Every function takes the folder and the file's name (for example
//! `myapp-recovery.json`), so an app's files keep the app's names.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeviceSeed {
    /// Hex-encoded 32-byte agent seed. Treat like a key: escrow it, export
    /// it to the user, never log it.
    pub device_seed_hex: String,
    /// Format version of this file itself.
    pub version: u32,
}

impl DeviceSeed {
    pub fn seed_bytes(&self) -> Result<[u8; 32], String> {
        let v = hex::decode(&self.device_seed_hex)
            .map_err(|e| format!("recovery file: bad seed hex: {}", e))?;
        v.try_into()
            .map_err(|_| "recovery file: seed is not 32 bytes".to_string())
    }
}

pub fn recovery_path(data_dir: &Path, file: &str) -> PathBuf {
    data_dir.join(file)
}

/// The name an outgoing seed's file is kept under when it is replaced:
/// `myapp-recovery.json` at `ts` is `myapp-recovery.replaced-<ts>.json`.
/// [`replaced_prefix`] matches every one of them.
pub fn replaced_name(file: &str, ts: u64) -> String {
    format!("{}{}.json", replaced_prefix(file), ts)
}

/// What every kept outgoing seed file's name starts with.
pub fn replaced_prefix(file: &str) -> String {
    format!("{}.replaced-", file.strip_suffix(".json").unwrap_or(file))
}

/// Load the device seed, or None when this install predates the scheme
/// (or is brand new). Corrupt files are an ERROR, never silently regenerated
/// - regenerating would orphan the agent the corrupt file described.
pub fn load(data_dir: &Path, file: &str) -> Result<Option<DeviceSeed>, String> {
    let p = recovery_path(data_dir, file);
    if !p.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&p)
        .map_err(|e| format!("recovery file unreadable: {}", e))?;
    let seed: DeviceSeed =
        serde_json::from_str(&raw).map_err(|e| format!("recovery file corrupt: {}", e))?;
    seed.seed_bytes()?; // validate now, loudly
    Ok(Some(seed))
}

/// Generate a fresh random seed WITHOUT persisting it. The re-key flow
/// commits the seed only after the old key-derived state is verifiably
/// wiped - generation and persistence are deliberately separate steps.
pub fn generate() -> Result<DeviceSeed, String> {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut seed).map_err(|e| format!("seed generation failed: {}", e))?;
    Ok(DeviceSeed { device_seed_hex: hex::encode(seed), version: 1 })
}

/// Generate a fresh random seed and persist it. Refuses to overwrite an
/// existing file - replacing a seed is an explicit adopt/re-key operation,
/// never a side effect.
pub fn generate_and_store(data_dir: &Path, file: &str) -> Result<DeviceSeed, String> {
    let p = recovery_path(data_dir, file);
    if p.exists() {
        return Err("recovery file already exists".into());
    }
    let ds = generate()?;
    store(data_dir, file, &ds)?;
    Ok(ds)
}

/// Replace the recovery file with `seed`, preserving whatever is there as a
/// timestamped sibling first. A key must never be silently destroyed - old
/// records encrypted to the old agent are unrecoverable without it, so the
/// adopt/re-key paths keep the outgoing material on disk.
pub fn replace(data_dir: &Path, file: &str, seed: &DeviceSeed) -> Result<(), String> {
    let p = recovery_path(data_dir, file);
    if p.exists() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = data_dir.join(replaced_name(file, ts));
        std::fs::rename(&p, &backup)
            .map_err(|e| format!("could not preserve the old recovery file: {}", e))?;
    }
    store(data_dir, file, seed)
}

/// The `app_keys` block both export emitters carry (canonical backup and the
/// data export): the means of authorship travels WITH the data (CAL).
/// Installs whose agent predates the app-held seed have nothing to escrow
/// yet and say so. A corrupt recovery file is an error - the caller decides
/// whether that blocks (backups do; see the escrow gate) - never silently
/// exported as "no seed". `no_seed_readme` is the note written for an
/// install with no seed to include, saying what the person can do in the app.
pub fn app_keys_json(data_dir: &Path, file: &str, no_seed_readme: &str) -> Result<serde_json::Value, String> {
    match load(data_dir, file)? {
        Some(seed) => Ok(serde_json::json!({
            "_readme": "The agent seed this device signs with. Import it on a new machine to keep authoring as the same agent. Keep any export of this file private.",
            "device_seed_hex": seed.device_seed_hex,
            "version": seed.version,
        })),
        None => Ok(serde_json::json!({
            "_readme": no_seed_readme,
            "device_seed_hex": serde_json::Value::Null,
        })),
    }
}

/// Persist a seed (adopt/re-key path). Writes via a temp file + rename so a
/// crash can never leave a half-written recovery file.
pub fn store(data_dir: &Path, file: &str, seed: &DeviceSeed) -> Result<(), String> {
    seed.seed_bytes()?; // never persist something unloadable
    let p = recovery_path(data_dir, file);
    let tmp = p.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(seed).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| format!("recovery file write failed: {}", e))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("recovery file rename failed: {}", e))?;
    Ok(())
}

/// The Ed25519 public key this seed gives: the same one a key store
/// derives when the seed is imported (libsodium's `crypto_sign_seed_keypair`).
/// A Holochain agent key is these 32 bytes with its prefix and location
/// (`AgentPubKey::from_raw_32`).
pub fn public_key(seed: &DeviceSeed) -> Result<[u8; 32], String> {
    let seed_bytes = seed.seed_bytes()?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed_bytes).verifying_key().to_bytes())
}

/// The seed to start with: the one on file, or a new one stored now.
pub fn load_or_create(data_dir: &Path, file: &str) -> Result<DeviceSeed, String> {
    match load(data_dir, file)? {
        Some(s) => Ok(s),
        None => generate_and_store(data_dir, file),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const FILE: &str = "myapp-recovery.json";
    const NO_SEED: &str = "No seed can be included. Re-key in the app.";

    #[test]
    fn generate_load_roundtrip_and_no_overwrite() {
        let dir = std::env::temp_dir().join(format!("fvc-seed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = generate_and_store(&dir, FILE).unwrap();
        let b = load(&dir, FILE).unwrap().expect("seed present");
        // No Debug on key material - compare without assert_eq.
        assert!(a == b, "roundtrip changed the seed");
        assert!(generate_and_store(&dir, FILE).is_err(), "must refuse overwrite");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_errors_never_regenerates() {
        let dir = std::env::temp_dir().join(format!("fvc-seed-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(recovery_path(&dir, FILE), "{not json").unwrap();
        assert!(load(&dir, FILE).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replace_preserves_the_old_file_with_a_timestamp() {
        let dir = std::env::temp_dir().join(format!("fvc-seed-replace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = generate_and_store(&dir, FILE).unwrap();
        let new = generate().unwrap();
        replace(&dir, FILE, &new).unwrap();
        let loaded = load(&dir, FILE).unwrap().expect("seed present");
        assert!(loaded == new, "replace must commit the incoming seed");
        let preserved = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("myapp-recovery.replaced-")
            })
            .count();
        assert_eq!(preserved, 1, "old seed must be preserved, never destroyed");
        let raw = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("myapp-recovery.replaced-")
            })
            .unwrap();
        let kept: DeviceSeed =
            serde_json::from_str(&std::fs::read_to_string(raw.path()).unwrap()).unwrap();
        assert!(kept == old, "preserved file must hold the outgoing seed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The v6 payload-shape contract: what both export emitters embed.
    #[test]
    fn app_keys_block_carries_the_seed_when_present() {
        let dir = std::env::temp_dir().join(format!("fvc-seed-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seed = generate_and_store(&dir, FILE).unwrap();
        let keys = app_keys_json(&dir, FILE, NO_SEED).unwrap();
        assert_eq!(
            keys["device_seed_hex"].as_str(),
            Some(seed.device_seed_hex.as_str())
        );
        assert_eq!(keys["version"].as_u64(), Some(1));
        assert!(keys["_readme"].as_str().unwrap().contains("same agent"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn app_keys_block_is_an_honest_null_for_legacy_installs() {
        let dir = std::env::temp_dir().join(format!("fvc-seed-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let keys = app_keys_json(&dir, FILE, NO_SEED).unwrap();
        assert!(keys["device_seed_hex"].is_null());
        assert!(keys["_readme"].as_str().unwrap().contains("Re-key"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn app_keys_block_errors_on_a_corrupt_file_never_null() {
        let dir = std::env::temp_dir().join(format!("fvc-seed-keyscorrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(recovery_path(&dir, FILE), "{not json").unwrap();
        assert!(app_keys_json(&dir, FILE, NO_SEED).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The key a seed gives is the one libsodium (and so the key store)
    /// derives: RFC 8032's first test vector.
    #[test]
    fn the_public_key_is_the_one_a_key_store_derives() {
        let seed = DeviceSeed { device_seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".into(), version: 1 };
        assert_eq!(hex::encode(public_key(&seed).unwrap()), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert!(public_key(&DeviceSeed { device_seed_hex: "zz".into(), version: 1 }).is_err());
    }

    #[test]
    fn replaced_files_keep_the_app_s_name() {
        assert_eq!(replaced_name("myapp-recovery.json", 7), "myapp-recovery.replaced-7.json");
        assert!(replaced_name("myapp-recovery.json", 7).starts_with(&replaced_prefix("myapp-recovery.json")));
    }
}
