//! Adopt and re-key: replace this install's device key, in an order that
//! cannot leave it half done; and the check that keeps a backup from
//! overwriting a key the person still needs.
//!
//! Two flows share one engine:
//!   - **Adopt** (the old device is gone): commit the seed kept in the
//!     person's Vault backup, so this device carries on as the SAME key.
//!   - **Re-key**: move an install onto a new seed the backup can carry.
//!
//! The ordering is the whole point: stop the processes that hold the old
//! key's files, wipe what was derived from that key with retries, VERIFY
//! the wipe, and only then commit the new seed, aborting with nothing
//! changed when the wipe cannot complete. Committing first restarts into a
//! half-wiped mix where the key store cannot start.
//!
//! The backup check ([`backup_escrow_gate`]): a backup REFUSES to overwrite
//! a Vault backup whose seed differs from this device's. Without it, a new
//! install's first backup would destroy the very seed the person needs to
//! adopt.
//!
//! Effects sit behind small traits ([`AdoptSeams`], [`EscrowProbe`]) so the
//! ordering and the decisions are unit-tested.

use crate::device_seed::DeviceSeed;
use crate::vault::VaultClient;
use std::path::{Path, PathBuf};

/// 20 attempts x 500 ms = 10 s per target for Windows to release file locks.
pub const WIPE_ATTEMPTS: usize = 20;
pub const SETTLE_MS: u64 = 1500;
const WIPE_RETRY_MS: u64 = 500;

/// Written when an adopt or re-key commits; tells the app after its restart
/// to walk the person through signing back in. Cleared when the identity
/// link is saved.
pub const RELINK_MARKER: &str = "adopt-relink-pending";

pub fn relink_marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RELINK_MARKER)
}

pub fn clear_relink_marker(data_dir: &Path) {
    let _ = std::fs::remove_file(relink_marker_path(data_dir));
}

/// Why an adopt or re-key did not happen. Nothing was changed unless it
/// says otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptError {
    /// The incoming seed is the one this device already uses.
    SameKey,
    /// The incoming seed is not a seed.
    BadSeed(String),
    /// A folder or file derived from the old key could not be removed.
    NotReleased { target: String, why: String },
    /// The wipe was done and the new seed could not be written.
    Commit(String),
}

impl std::fmt::Display for AdoptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdoptError::SameKey => write!(f, "This device already uses that key - nothing to restore."),
            AdoptError::BadSeed(e) => write!(f, "{e}"),
            AdoptError::NotReleased { target, why } => write!(f, "Could not release this device's Holochain state ({target}: {why}). Close and reopen the app, then try again - your current key and sign-in are unchanged."),
            AdoptError::Commit(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AdoptError {}

/// Why a backup was held back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// The Vault's backup could not be read first: when in doubt, never write.
    CheckFailed(String),
    /// The Vault's backup holds a different key than this device's.
    OtherKey,
    /// The Vault's backup holds a key and this install has none.
    NoLocalKey,
    /// This device's seed file cannot be read.
    LocalUnreadable(String),
}

impl std::fmt::Display for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Held::CheckFailed(e) => write!(f, "backup held: could not check the Vault's escrowed key first ({e}) - when in doubt, never write"),
            Held::OtherKey => write!(f, "backup held: your Vault backup escrows a different authorship key than this device's. Restore the key first - overwriting would destroy it."),
            Held::NoLocalKey => write!(f, "backup held: your Vault backup escrows an authorship key this install does not have. Restore the key first - overwriting would destroy it."),
            Held::LocalUnreadable(e) => write!(f, "backup held: this device's recovery file is unreadable ({e}) - refusing to overwrite the escrowed key"),
        }
    }
}

impl std::error::Error for Held {}

// ── The adopt engine (ordering under test) ─────────────────────────────

#[allow(async_fn_in_trait)]
pub trait AdoptSeams {
    /// Revoke this install's own identity-link entry while the conductor can
    /// still sign as the outgoing agent (the superseded link is revoked as
    /// active but retained as history - delete_entry tombstones, it never
    /// erases).
    async fn revoke_outgoing_link(&self) -> Result<(), String>;
    /// Stop every process that holds the old key's files (the conductors
    /// and key stores), in the way that works on this system.
    async fn stop_processes(&self);
    async fn sleep_ms(&self, ms: u64);
    fn target_exists(&self, target: &str) -> bool;
    fn remove_target(&self, target: &str) -> Result<(), String>;
    /// Commit the incoming seed as the recovery file (old file preserved
    /// with a timestamp).
    fn commit_seed(&self, seed: &DeviceSeed) -> Result<(), String>;
    /// Drop the outgoing identity binding (identity-link.json +
    /// profile-cache.json) and leave the step-2 relink marker.
    fn finish_binding_swap(&self);
}

/// Replace the device key with `incoming`. `targets` is everything derived
/// from the outgoing key, wiped before the new seed is committed: the key
/// store and conductor folders and the key store's passphrase file. The
/// seed file itself is NOT a target (it is what the commit replaces, the
/// old one kept beside it), and neither are the identity link and cached
/// profile (they go in the binding swap, after the wipe is verified, so an
/// adopt that aborts leaves a sign-in that still works).
pub async fn run_adopt<S: AdoptSeams>(
    seams: &S,
    targets: &[&str],
    incoming: &DeviceSeed,
    local: Option<&DeviceSeed>,
) -> Result<(), AdoptError> {
    // Validate before touching anything.
    incoming.seed_bytes().map_err(AdoptError::BadSeed)?;
    if local == Some(incoming) {
        return Err(AdoptError::SameKey);
    }

    // 1. Supersede the outgoing agent's link while it can still sign the
    //    revocation. Best-effort: a failed revocation leaves an orphaned
    //    link entry (recoverable, known-deferred cleanup); blocking a
    //    machine-death restore on it is worse.
    if let Err(e) = seams.revoke_outgoing_link().await {
        log::warn!("[adopt] could not revoke the outgoing identity link: {}", e);
    }

    // 2. Stop conductor + lair so their databases aren't held open, then
    //    give the OS a beat - Windows releases file locks a moment after
    //    the processes die.
    seams.stop_processes().await;
    seams.sleep_ms(SETTLE_MS).await;

    // 3. Wipe the key-derived state BEFORE committing the new seed, retrying
    //    while locks release and VERIFYING each removal - remove_dir_all can
    //    report success on Windows while children are still pending-delete.
    //    On persistent failure abort with the old seed and sign-in intact.
    for target in targets {
        let mut removed = false;
        let mut last_err = String::from("still present");
        for _ in 0..WIPE_ATTEMPTS {
            if !seams.target_exists(target) {
                removed = true;
                break;
            }
            match seams.remove_target(target) {
                Ok(()) => {
                    if !seams.target_exists(target) {
                        removed = true;
                        break;
                    }
                    last_err = "removal reported success but the target is still present".into();
                }
                Err(e) => last_err = e,
            }
            seams.sleep_ms(WIPE_RETRY_MS).await;
        }
        if !removed {
            return Err(AdoptError::NotReleased { target: target.to_string(), why: last_err });
        }
    }

    // 4. Only now commit the new seed, then swap the identity binding and
    //    leave the step-2 marker for the post-restart sign-in prompt.
    seams.commit_seed(incoming).map_err(AdoptError::Commit)?;
    seams.finish_binding_swap();
    Ok(())
}

// ── The backup escrow gate (decisions under test) ──────────────────────

/// What the Vault's backup slot holds, seed-wise.
pub enum EscrowedSeed {
    /// A seed is escrowed (hex string as stored - validity is the
    /// comparison's problem, and an invalid stored seed can never equal a
    /// valid local one, so it refuses).
    Seed(String),
    /// No backup stored at all - an empty slot is safe to write into.
    NoBackup,
    /// A backup exists but carries no adoptable seed (a legacy install's
    /// explicit null, or a pre-seed backup format). Data-only backups were
    /// always overwritten hourly; nothing key-shaped is at risk.
    DataOnly,
}

#[allow(async_fn_in_trait)]
pub trait EscrowProbe {
    async fn escrowed_seed(&self) -> Result<EscrowedSeed, String>;
}

/// Refuse a canonical-backup write whenever it would destroy an escrowed
/// seed that is not this device's. This is what keeps the adopt window
/// safe: a fresh install links, its hourly backup fires, and without this
/// gate that backup would replace the lost machine's escrowed seed before
/// the user ever saw the restore offer.
pub async fn backup_escrow_gate<P: EscrowProbe>(probe: &P, local: Result<Option<DeviceSeed>, String>) -> Result<(), Held> {
    let escrowed = probe.escrowed_seed().await.map_err(Held::CheckFailed)?;
    match escrowed {
        EscrowedSeed::NoBackup | EscrowedSeed::DataOnly => Ok(()),
        EscrowedSeed::Seed(theirs) => match local {
            Ok(Some(mine)) if mine.device_seed_hex == theirs => Ok(()),
            Ok(Some(_)) => Err(Held::OtherKey),
            Ok(None) => Err(Held::NoLocalKey),
            Err(e) => Err(Held::LocalUnreadable(e)),
        },
    }
}

/// Classify a retrieved canonical-backup payload's `app_keys` block.
/// A payload that isn't even an object is an error, never "safe to
/// overwrite" - when in doubt, never write.
pub fn classify_escrow_payload(data: &serde_json::Value) -> Result<EscrowedSeed, String> {
    if !data.is_object() {
        return Err("escrow_unreadable: backup payload is not an object".into());
    }
    match data.get("app_keys") {
        None => Ok(EscrowedSeed::DataOnly),
        Some(keys) => match keys.get("device_seed_hex") {
            Some(serde_json::Value::String(s)) => Ok(EscrowedSeed::Seed(s.clone())),
            Some(serde_json::Value::Null) => Ok(EscrowedSeed::DataOnly),
            _ => Err("escrow_unreadable: app_keys carries no recognisable seed".into()),
        },
    }
}

// ── The Vault's side, and the usual file effects ──────────────────────

/// The app's backup in the person's Vault.
pub struct VaultEscrowProbe {
    pub vault: VaultClient,
    /// The app's Flowsta client id.
    pub client_id: String,
}

impl VaultEscrowProbe {
    /// The app's backup payload in the linked Vault; None when there is none.
    pub async fn retrieve(&self) -> Result<Option<serde_json::Value>, String> {
        let resp = self
            .vault
            .http()
            .post(format!("{}/backup/retrieve", self.vault.base_url().await))
            .timeout(std::time::Duration::from_secs(5))
            .json(&serde_json::json!({ "client_id": self.client_id }))
            .send()
            .await
            .map_err(|e| format!("vault unreachable: {}", e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            return Err(body["error"].as_str().unwrap_or("retrieve_failed").to_string());
        }
        let mut v: serde_json::Value = resp.json().await.map_err(|e| format!("bad retrieve response: {}", e))?;
        Ok(Some(v["data"].take()))
    }
}

impl EscrowProbe for VaultEscrowProbe {
    async fn escrowed_seed(&self) -> Result<EscrowedSeed, String> {
        match self.retrieve().await? {
            None => Ok(EscrowedSeed::NoBackup),
            Some(data) => classify_escrow_payload(&data),
        }
    }
}

/// Whether `target` is still in the profile's folder ([`AdoptSeams::target_exists`]).
pub fn target_exists(data_dir: &Path, target: &str) -> bool {
    data_dir.join(target).exists()
}

/// Remove a folder or file of the profile ([`AdoptSeams::remove_target`]);
/// one that is already gone is removed.
pub fn remove_target(data_dir: &Path, target: &str) -> Result<(), String> {
    let p = data_dir.join(target);
    let res = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
    match res {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Drop the outgoing identity's link and cached profile and leave the
/// marker for signing back in ([`AdoptSeams::finish_binding_swap`]).
pub fn finish_binding_swap(data_dir: &Path) {
    crate::identity::delete_identity_link(data_dir);
    crate::identity::delete_cached_profile(data_dir);
    if let Err(e) = std::fs::write(relink_marker_path(data_dir), b"") {
        log::warn!("[adopt] could not write the relink marker: {}", e);
    }
}

#[cfg(test)]
mod tests {
    const WIPE_TARGETS: &[&str] = &["conductor", "lair", "conductor-07", "lair-07", "lair-passphrase"];
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashSet, VecDeque};

    fn seed(byte: &str) -> DeviceSeed {
        DeviceSeed { device_seed_hex: byte.repeat(32), version: 1 }
    }

    struct Scripted {
        /// Targets currently "on disk".
        present: RefCell<HashSet<String>>,
        /// Scripted outcome per remove_target call (one shared queue, in call
        /// order); exhausted queue defaults to Ok.
        removals: RefCell<VecDeque<Result<(), String>>>,
        /// When false, a successful removal does NOT clear `present` - the
        /// lying-remove case (Windows remove_dir_all returning Ok with
        /// children still pending-delete).
        honest_removals: bool,
        revoke: RefCell<VecDeque<Result<(), String>>>,
        commit: RefCell<VecDeque<Result<(), String>>>,
        calls: RefCell<Vec<String>>,
        retry_sleeps: RefCell<usize>,
    }

    impl Scripted {
        fn new(present: &[&str]) -> Self {
            Self {
                present: RefCell::new(present.iter().map(|s| s.to_string()).collect()),
                removals: RefCell::new(VecDeque::new()),
                honest_removals: true,
                revoke: RefCell::new(VecDeque::new()),
                commit: RefCell::new(VecDeque::new()),
                calls: RefCell::new(Vec::new()),
                retry_sleeps: RefCell::new(0),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl AdoptSeams for Scripted {
        async fn revoke_outgoing_link(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("revoke".into());
            self.revoke.borrow_mut().pop_front().unwrap_or(Ok(()))
        }
        async fn stop_processes(&self) {
            self.calls.borrow_mut().push("stop".into());
        }
        async fn sleep_ms(&self, ms: u64) {
            if ms == SETTLE_MS {
                self.calls.borrow_mut().push("settle".into());
            } else {
                *self.retry_sleeps.borrow_mut() += 1;
            }
        }
        fn target_exists(&self, target: &str) -> bool {
            self.present.borrow().contains(target)
        }
        fn remove_target(&self, target: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("remove:{}", target));
            let r = self.removals.borrow_mut().pop_front().unwrap_or(Ok(()));
            if r.is_ok() && self.honest_removals {
                self.present.borrow_mut().remove(target);
            }
            r
        }
        fn commit_seed(&self, _seed: &DeviceSeed) -> Result<(), String> {
            self.calls.borrow_mut().push("commit".into());
            self.commit.borrow_mut().pop_front().unwrap_or(Ok(()))
        }
        fn finish_binding_swap(&self) {
            self.calls.borrow_mut().push("swap".into());
        }
    }

    #[tokio::test]
    async fn happy_path_order_is_revoke_stop_settle_wipe_commit_swap() {
        let s = Scripted::new(&["conductor", "lair", "lair-passphrase"]);
        run_adopt(&s, WIPE_TARGETS, &seed("aa"), Some(&seed("bb"))).await.unwrap();
        assert_eq!(
            s.calls(),
            vec![
                "revoke",
                "stop",
                "settle",
                "remove:conductor",
                "remove:lair",
                "remove:lair-passphrase",
                "commit",
                "swap",
            ]
        );
    }

    #[tokio::test]
    async fn the_07_line_is_wiped_with_the_06_line() {
        let s = Scripted::new(&["conductor", "lair", "conductor-07", "lair-07", "lair-passphrase"]);
        run_adopt(&s, WIPE_TARGETS, &seed("aa"), Some(&seed("bb"))).await.unwrap();
        let removed: Vec<String> = s.calls().into_iter().filter(|c| c.starts_with("remove:")).collect();
        assert_eq!(
            removed,
            vec!["remove:conductor", "remove:lair", "remove:conductor-07", "remove:lair-07", "remove:lair-passphrase"]
        );
    }

    #[tokio::test]
    async fn same_seed_refuses_before_touching_anything() {
        let s = Scripted::new(&["conductor", "lair", "lair-passphrase"]);
        let err = run_adopt(&s, WIPE_TARGETS, &seed("aa"), Some(&seed("aa"))).await.unwrap_err().to_string();
        assert!(err.contains("nothing to restore"), "{}", err);
        assert!(s.calls().is_empty(), "must not touch anything: {:?}", s.calls());
    }

    #[tokio::test]
    async fn invalid_incoming_seed_refuses_before_touching_anything() {
        let s = Scripted::new(&["conductor"]);
        let bad = DeviceSeed { device_seed_hex: "not-hex".into(), version: 1 };
        assert!(run_adopt(&s, WIPE_TARGETS, &bad, None).await.is_err());
        assert!(s.calls().is_empty());
    }

    #[tokio::test]
    async fn revoke_failure_is_nonfatal_and_order_continues() {
        let s = Scripted::new(&["conductor", "lair", "lair-passphrase"]);
        s.revoke.borrow_mut().push_back(Err("conductor not ready".into()));
        run_adopt(&s, WIPE_TARGETS, &seed("aa"), None).await.unwrap();
        let calls = s.calls();
        assert_eq!(calls.first().map(String::as_str), Some("revoke"));
        assert!(calls.contains(&"commit".to_string()));
        assert!(calls.contains(&"swap".to_string()));
    }

    #[tokio::test]
    async fn locked_target_retries_until_the_lock_releases() {
        let s = Scripted::new(&["conductor", "lair", "lair-passphrase"]);
        s.removals.borrow_mut().push_back(Err("locked".into()));
        s.removals.borrow_mut().push_back(Err("locked".into()));
        // Third attempt (default Ok) succeeds; later targets default Ok too.
        run_adopt(&s, WIPE_TARGETS, &seed("aa"), None).await.unwrap();
        let calls = s.calls();
        let conductor_removes = calls.iter().filter(|c| *c == "remove:conductor").count();
        assert_eq!(conductor_removes, 3, "{:?}", calls);
        assert!(*s.retry_sleeps.borrow() >= 2);
        assert!(calls.contains(&"commit".to_string()));
    }

    #[tokio::test]
    async fn unwipeable_target_aborts_with_nothing_committed() {
        let s = Scripted::new(&["conductor", "lair", "lair-passphrase"]);
        for _ in 0..WIPE_ATTEMPTS {
            s.removals.borrow_mut().push_back(Err("held open".into()));
        }
        let err = run_adopt(&s, WIPE_TARGETS, &seed("aa"), Some(&seed("bb"))).await.unwrap_err().to_string();
        assert!(err.contains("unchanged"), "abort copy must say nothing changed: {}", err);
        let calls = s.calls();
        assert!(!calls.contains(&"commit".to_string()), "commit must never run: {:?}", calls);
        assert!(!calls.contains(&"swap".to_string()));
        // It kept retrying the first target and never advanced to the next.
        assert!(!calls.contains(&"remove:lair".to_string()));
    }

    #[tokio::test]
    async fn lying_removal_is_caught_by_verification() {
        // Every removal reports Ok but the target never leaves the disk -
        // the real Windows failure mode. The exists() verification must
        // catch it and abort without committing.
        let mut s = Scripted::new(&["conductor", "lair", "lair-passphrase"]);
        s.honest_removals = false;
        let err = run_adopt(&s, WIPE_TARGETS, &seed("aa"), None).await.unwrap_err().to_string();
        assert!(err.contains("still present"), "{}", err);
        let calls = s.calls();
        assert_eq!(
            calls.iter().filter(|c| *c == "remove:conductor").count(),
            WIPE_ATTEMPTS
        );
        assert!(!calls.contains(&"commit".to_string()));
    }

    #[tokio::test]
    async fn absent_targets_skip_removal_and_commit_runs() {
        let s = Scripted::new(&[]);
        run_adopt(&s, WIPE_TARGETS, &seed("aa"), None).await.unwrap();
        assert_eq!(s.calls(), vec!["revoke", "stop", "settle", "commit", "swap"]);
    }

    #[tokio::test]
    async fn commit_failure_propagates_and_swap_never_runs() {
        let s = Scripted::new(&[]);
        s.commit.borrow_mut().push_back(Err("disk full".into()));
        let err = run_adopt(&s, WIPE_TARGETS, &seed("aa"), None).await.unwrap_err().to_string();
        assert!(err.contains("disk full"));
        assert!(!s.calls().contains(&"swap".to_string()));
    }

    // ── The backup escrow gate ──────────────────────────────────────────

    struct ScriptedProbe {
        result: RefCell<VecDeque<Result<EscrowedSeed, String>>>,
    }
    impl ScriptedProbe {
        fn one(r: Result<EscrowedSeed, String>) -> Self {
            Self { result: RefCell::new(VecDeque::from([r])) }
        }
    }
    impl EscrowProbe for ScriptedProbe {
        async fn escrowed_seed(&self) -> Result<EscrowedSeed, String> {
            self.result
                .borrow_mut()
                .pop_front()
                .expect("gate probed the escrow more often than scripted")
        }
    }

    #[tokio::test]
    async fn gate_allows_matching_seed_empty_slot_and_data_only() {
        for escrowed in [
            Ok(EscrowedSeed::Seed("aa".repeat(32))),
            Ok(EscrowedSeed::NoBackup),
            Ok(EscrowedSeed::DataOnly),
        ] {
            let p = ScriptedProbe::one(escrowed);
            backup_escrow_gate(&p, Ok(Some(seed("aa")))).await.unwrap();
        }
    }

    #[tokio::test]
    async fn gate_refuses_foreign_seed_missing_local_and_unreadable_local() {
        let cases: Vec<Result<Option<DeviceSeed>, String>> = vec![
            Ok(Some(seed("bb"))),
            Ok(None),
            Err("corrupt".into()),
        ];
        for local in cases {
            let p = ScriptedProbe::one(Ok(EscrowedSeed::Seed("aa".repeat(32))));
            let err = backup_escrow_gate(&p, local).await.unwrap_err().to_string();
            assert!(err.contains("backup held"), "{}", err);
        }
    }

    #[tokio::test]
    async fn gate_refuses_when_the_probe_fails() {
        let p = ScriptedProbe::one(Err("vault unreachable".into()));
        let err = backup_escrow_gate(&p, Ok(Some(seed("aa")))).await.unwrap_err().to_string();
        assert!(err.contains("never write"), "{}", err);
    }

    #[test]
    fn classify_escrow_payload_matrix() {
        let seeded = serde_json::json!({"app_keys": {"device_seed_hex": "ab"}});
        assert!(matches!(
            classify_escrow_payload(&seeded),
            Ok(EscrowedSeed::Seed(s)) if s == "ab"
        ));
        let legacy_null = serde_json::json!({"app_keys": {"device_seed_hex": null}});
        assert!(matches!(classify_escrow_payload(&legacy_null), Ok(EscrowedSeed::DataOnly)));
        let pre_seed = serde_json::json!({"version": 1, "cells": []});
        assert!(matches!(classify_escrow_payload(&pre_seed), Ok(EscrowedSeed::DataOnly)));
        let not_object = serde_json::json!(null);
        assert!(classify_escrow_payload(&not_object).is_err());
        let weird = serde_json::json!({"app_keys": {"device_seed_hex": 7}});
        assert!(classify_escrow_payload(&weird).is_err());
    }
}
