//! Finding the right Flowsta Vault on this device.
//!
//! The Vault binds 27777, or the next port up when that is taken. Loopback
//! ports are shared by every user account on a computer: one account's Vault
//! can sit on 27777 while the person's own is on 27778, so "the first port
//! that answers" can be the wrong Vault. So: ask all three ports at once,
//! drop any Vault whose listening process belongs to another OS user, and
//! prefer the unlocked one, then an initialized (locked) one.
//!
//! When the owner of a listener cannot be read (a tool missing, a localized
//! netstat) the Vault is kept: never lose the person's own Vault to a failed
//! check. Verdicts are cached per port for a minute.
//!
//! Once the person has linked the app, the Vault tells it apart from every
//! other app by its link token ([`VaultClient::set_link_token`]) and its
//! client id ([`VaultConfig::client_id`]). [`VaultClient::get`] and
//! [`VaultClient::post`] put both on a request; a Vault from before link
//! tokens ignores them.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The ports a Vault listens on: the first that is free.
pub const VAULT_PORTS: [u16; 3] = [27777, 27778, 27779];

/// How an app reaches the Vault.
#[derive(Clone, Debug)]
pub struct VaultConfig {
    /// The Origin header every request carries. Use an origin of the app's
    /// own (for example `yourapp://app`), the one its link in the Vault was
    /// made from: the Vault records the origin that asked for a link, and
    /// answers that link's token only to the same origin. A request with no
    /// origin the Vault knows is answered as a stranger (`/status` without
    /// the display name and picture, other routes refused).
    ///
    /// When the link was made from the app's webview, the Vault recorded
    /// the webview's origin, and Rust has to present that one instead: see
    /// [`tauri_origin`].
    pub origin: String,
    /// One port to ask instead of all three: for a test build that must talk
    /// to one Vault among several on the machine. `None` in a release.
    pub only_port: Option<u16>,
    /// The app's Flowsta client id. Sent with every call that
    /// [`VaultClient::get`] and [`VaultClient::post`] make, so the Vault
    /// can tell this app from another one that presents the same origin.
    pub client_id: Option<String>,
}

/// The origin a Tauri v2 webview presents: the dev server's (`dev_url`,
/// from `tauri.conf.json`) under `tauri dev`, the bundled one in every
/// built app. Pass `tauri::is_dev()`.
///
/// Calls made from Rust should present an origin of the app's own (see
/// [`VaultConfig::origin`]). This one is for the case where Rust must
/// present the same origin as the app's webview: the link was made from the
/// webview, so the Vault recorded the webview's origin, and a link token
/// made there is accepted only from that origin. Every Tauri app's webview
/// presents this same origin, so set [`VaultConfig::client_id`] and the
/// link token with it.
pub fn tauri_origin(is_dev: bool, dev_url: &str) -> String {
    if is_dev {
        dev_url.trim_end_matches('/').to_string()
    } else if cfg!(target_os = "windows") {
        "http://tauri.localhost".to_string()
    } else {
        "tauri://localhost".to_string()
    }
}

/// A handle on the person's Vault (cheap to clone; clones share what was
/// last found).
#[derive(Clone)]
pub struct VaultClient {
    inner: Arc<Inner>,
}

struct Inner {
    config: VaultConfig,
    http: reqwest::Client,
    last_port: Mutex<Option<u16>>,
    link_token: Mutex<Option<String>>,
}

/// The Vault's routes that read the link token and the client id. `/status`
/// is among them, and is sent them only when there is a token.
const IDENTITY_ROUTES: [&str; 14] = [
    "/status",
    "/authenticate",
    "/sign",
    "/sign-document",
    "/backup",
    "/backup/retrieve",
    "/backup/delete",
    "/backup/list",
    "/app-secret",
    "/devices",
    "/link-status",
    "/revoke-identity",
    "/sign-node-manifest",
    "/sign-release-manifest",
];

/// What a request to `path` says about the app: its link token and its
/// client id, each when known. Nothing for a route that does not read them,
/// and nothing for `/status` while there is no token.
fn identity_fields(path: &str, client_id: Option<&str>, link_token: Option<&str>) -> Vec<(&'static str, String)> {
    let path = path.trim_end_matches('/');
    if !IDENTITY_ROUTES.contains(&path) || (path == "/status" && link_token.is_none()) {
        return Vec::new();
    }
    let mut fields = Vec::new();
    if let Some(token) = link_token {
        fields.push(("link_token", token.to_string()));
    }
    if let Some(id) = client_id {
        fields.push(("client_id", id.to_string()));
    }
    fields
}

/// The path of a Vault URL, or "" when it is not a URL.
fn url_path(url: &str) -> String {
    reqwest::Url::parse(url).map(|u| u.path().to_string()).unwrap_or_default()
}

/// Why the Vault refused a call (a 403 with one of these as its `error`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The link token matches no link in this Vault: the person removed the
    /// app there, or linked it again since. Forget the token and sign in
    /// again.
    InvalidLinkToken,
    /// The app's link answers only to its link token, and the request
    /// carried none.
    LinkTokenRequired,
    /// Several apps on this computer present this origin, and the request
    /// named none of them: set [`VaultConfig::client_id`].
    AppAmbiguous,
    /// The app's maker registered the origins it may link from, and this
    /// request's origin is not one of them.
    OriginNotRegistered,
    /// The request was not addressed to the Vault on this computer.
    NotAddressedHere,
}

impl Refused {
    /// The refusal a Vault's `error` code names, if it is one of these.
    pub fn from_code(code: &str) -> Option<Refused> {
        match code {
            "invalid_link_token" => Some(Refused::InvalidLinkToken),
            "link_token_required" => Some(Refused::LinkTokenRequired),
            "app_ambiguous" => Some(Refused::AppAmbiguous),
            "origin_not_registered" => Some(Refused::OriginNotRegistered),
            "not_addressed_here" => Some(Refused::NotAddressedHere),
            _ => None,
        }
    }

    /// The refusal in a Vault's answer: its status and its JSON body.
    pub fn from_answer(status: reqwest::StatusCode, body: &serde_json::Value) -> Option<Refused> {
        if status != reqwest::StatusCode::FORBIDDEN {
            return None;
        }
        Refused::from_code(body["error"].as_str()?)
    }

    /// The Vault's `error` code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Refused::InvalidLinkToken => "invalid_link_token",
            Refused::LinkTokenRequired => "link_token_required",
            Refused::AppAmbiguous => "app_ambiguous",
            Refused::OriginNotRegistered => "origin_not_registered",
            Refused::NotAddressedHere => "not_addressed_here",
        }
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::InvalidLinkToken => write!(f, "Flowsta Vault no longer has this app's link. Sign in with Flowsta again."),
            Refused::LinkTokenRequired => write!(f, "Flowsta Vault needs this app's link token, and the request carried none. Sign in with Flowsta again."),
            Refused::AppAmbiguous => write!(f, "Several apps on this computer use the same origin, and the request did not say which one it is from."),
            Refused::OriginNotRegistered => write!(f, "This app's origin is not one its maker registered with Flowsta."),
            Refused::NotAddressedHere => write!(f, "The request was not addressed to the Flowsta Vault on this computer."),
        }
    }
}

impl std::error::Error for Refused {}

/// What one Vault answered. `port` is where it lives.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VaultProbe {
    pub port: u16,
    pub url: String,
    pub unlocked: bool,
    pub initialized: bool,
    pub agent_pub_key: Option<String>,
    pub display_name: Option<String>,
    pub profile_picture: Option<String>,
}

impl VaultProbe {
    fn from_status(port: u16, v: &serde_json::Value) -> VaultProbe {
        VaultProbe {
            port,
            url: format!("http://127.0.0.1:{port}"),
            unlocked: v["unlocked"].as_bool().unwrap_or(false),
            initialized: v["initialized"].as_bool().unwrap_or(true),
            agent_pub_key: v["agent_pub_key"].as_str().map(String::from),
            display_name: v["display_name"].as_str().map(String::from),
            profile_picture: v["profile_picture"].as_str().map(String::from),
        }
    }
}

impl VaultClient {
    pub fn new(config: VaultConfig) -> Result<VaultClient, String> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ORIGIN,
            reqwest::header::HeaderValue::from_str(&config.origin).map_err(|e| format!("the origin is not a header value: {e}"))?,
        );
        let http = reqwest::Client::builder().default_headers(headers).build().map_err(|e| format!("http client: {e}"))?;
        Ok(VaultClient { inner: Arc::new(Inner { config, http, last_port: Mutex::new(None), link_token: Mutex::new(None) }) })
    }

    /// The origin requests carry.
    pub fn origin(&self) -> &str {
        &self.inner.config.origin
    }

    /// The one port this client asks, when it is pinned to one.
    pub fn only_port(&self) -> Option<u16> {
        self.inner.config.only_port
    }

    /// The app's Flowsta client id, when the config named one.
    pub fn client_id(&self) -> Option<&str> {
        self.inner.config.client_id.as_deref()
    }

    /// Keep the link token the Vault gave when the person linked this app
    /// (the `link_token` in the answer of `/link-identity`), or forget it
    /// with `None` once the link is removed. Every clone of this client
    /// sends it from then on. The app stores the token itself, with the
    /// profile it belongs to, and sets it again at each start.
    pub fn set_link_token(&self, token: Option<String>) {
        *self.inner.link_token.lock().unwrap() = token.filter(|t| !t.is_empty());
    }

    /// The link token calls carry now.
    pub fn link_token(&self) -> Option<String> {
        self.inner.link_token.lock().unwrap().clone()
    }

    /// The HTTP client, with the origin on every request and nothing else:
    /// for a call that must not say which app it is from. Every other call
    /// goes through [`VaultClient::get`] or [`VaultClient::post`].
    pub fn http(&self) -> &reqwest::Client {
        &self.inner.http
    }

    /// A GET to a Vault URL, with the link token and the client id as query
    /// parameters when they are known and the route reads them.
    pub fn get(&self, url: &str) -> reqwest::RequestBuilder {
        let fields = identity_fields(&url_path(url), self.client_id(), self.link_token().as_deref());
        let request = self.inner.http.get(url);
        if fields.is_empty() {
            request
        } else {
            request.query(&fields)
        }
    }

    /// A POST of a JSON object to a Vault URL, with the link token and the
    /// client id added to the object when they are known and the route
    /// reads them. A field the object already has is left as it is.
    pub fn post(&self, url: &str, mut body: serde_json::Value) -> reqwest::RequestBuilder {
        if let Some(object) = body.as_object_mut() {
            for (name, value) in identity_fields(&url_path(url), self.client_id(), self.link_token().as_deref()) {
                object.entry(name).or_insert(serde_json::Value::String(value));
            }
        }
        self.inner.http.post(url).json(&body)
    }

    /// One Vault's `/status`. With `as_app`, the request says which app it
    /// is from; an HTTP refusal of that is asked again without, so a token
    /// the Vault no longer knows never makes the Vault look absent.
    async fn ask_status(&self, port: u16, timeout: Duration, as_app: bool) -> Option<serde_json::Value> {
        let url = format!("http://127.0.0.1:{port}/status");
        let mut resp = if as_app { self.get(&url) } else { self.inner.http.get(&url) }.timeout(timeout).send().await.ok()?;
        if as_app && !resp.status().is_success() {
            resp = self.inner.http.get(&url).timeout(timeout).send().await.ok()?;
        }
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<serde_json::Value>().await.ok()
    }

    /// Every Vault of THIS OS user answering on this device, all three
    /// ports asked at once.
    ///
    /// The link token goes only to a Vault whose listening process was
    /// checked as this user's: a port not yet checked is asked without it
    /// first, and asked again with it once the check has passed.
    async fn probe_vaults(&self, timeout: Duration) -> Vec<VaultProbe> {
        let has_token = self.link_token().is_some();
        let one = |port: u16| async move {
            let as_app = has_token && checked_as_mine(port);
            let v = self.ask_status(port, timeout, as_app).await?;
            Some((VaultProbe::from_status(port, &v), as_app))
        };
        let found = match self.inner.config.only_port {
            Some(port) => vec![one(port).await],
            None => {
                let (a, b, c) = tokio::join!(one(VAULT_PORTS[0]), one(VAULT_PORTS[1]), one(VAULT_PORTS[2]));
                vec![a, b, c]
            }
        };
        let mut mine = Vec::new();
        for (mut p, asked_as_app) in found.into_iter().flatten() {
            if vault_is_mine(p.port).await {
                if has_token && !asked_as_app {
                    if let Some(v) = self.ask_status(p.port, timeout, true).await {
                        p = VaultProbe::from_status(p.port, &v);
                    }
                }
                mine.push(p);
            }
        }
        mine
    }

    /// The Vault to talk to right now, or None when none of this user's
    /// Vaults answers. Remembers the port for [`VaultClient::base_url`].
    pub async fn find(&self, timeout: Duration) -> Option<VaultProbe> {
        let answers = self.probe_vaults(timeout).await;
        let best = pick_vault(&answers).cloned();
        *self.inner.last_port.lock().unwrap() = best.as_ref().map(|p| p.port);
        best
    }

    /// Base URL for a Vault call: a fresh sweep when possible, else the
    /// last port that answered, else the default port (the caller's own
    /// error copy then says the Vault is unreachable).
    pub async fn base_url(&self) -> String {
        if let Some(p) = self.find(Duration::from_millis(1500)).await {
            return p.url;
        }
        let port = self.inner.last_port.lock().unwrap().unwrap_or(VAULT_PORTS[0]);
        format!("http://127.0.0.1:{port}")
    }

    /// Whether a Vault is unlocked right now, and as which identity:
    /// `None` when none answers.
    pub async fn live_identity(&self) -> Option<(bool, Option<String>)> {
        self.find(Duration::from_secs(3)).await.map(|p| (p.unlocked, p.agent_pub_key))
    }
}

/// Unlocked first, then initialized (locked), then any; ties to the lower port.
fn pick_vault(answers: &[VaultProbe]) -> Option<&VaultProbe> {
    answers
        .iter()
        .find(|p| p.unlocked)
        .or_else(|| answers.iter().find(|p| p.initialized))
        .or_else(|| answers.first())
}

// ── Opening the Vault ─────────────────────────────────────────────

/// Open the Flowsta Vault app when it is installed and not running, so the
/// person does not have to go and find it during sign-in. Tries the usual
/// install place on each system; an error means it could not be found or
/// started (the app then asks the person to open it). On Linux the Vault
/// starts without the variables named in `strip_env`: it decides its own
/// window's drawing and must not inherit what this app set for its own.
pub fn launch_vault(strip_env: &[&str]) -> Result<(), String> {
    use std::process::Command;
    let _ = strip_env;

    #[cfg(target_os = "macos")]
    {
        Command::new("open").args(["-a", "Flowsta Vault"]).spawn().map(|_| ()).map_err(|e| format!("Could not open Flowsta Vault: {e}"))
    }

    #[cfg(target_os = "linux")]
    {
        // Packaged installs (.deb/.rpm) put `flowsta-vault` on PATH.
        let mut vault = Command::new("flowsta-vault");
        for var in strip_env {
            vault.env_remove(var);
        }
        vault.spawn().map(|_| ()).map_err(|e| format!("Could not open Flowsta Vault: {e}"))
    }

    #[cfg(target_os = "windows")]
    {
        // The installer puts the app under <install root>/Flowsta Vault.
        for var in ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"] {
            if let Ok(base) = std::env::var(var) {
                let path = std::path::Path::new(&base).join("Flowsta Vault").join("Flowsta Vault.exe");
                if path.exists() {
                    return Command::new(&path).spawn().map(|_| ()).map_err(|e| format!("Could not open Flowsta Vault: {e}"));
                }
            }
        }
        Err("Could not find Flowsta Vault. Please open it manually.".into())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Unsupported platform".into())
    }
}

// ── The relaunch marker ───────────────────────────────────────────

/// Where an app notes, before restarting itself, that the restart was asked
/// for (to open as the identity the Vault now has unlocked).
pub fn relaunch_marker_path(device_root: &std::path::Path) -> std::path::PathBuf {
    device_root.join("relaunch-into-identity")
}

/// Note that the restart about to happen was asked for.
pub fn write_relaunch_marker(device_root: &std::path::Path) -> std::io::Result<()> {
    std::fs::write(relaunch_marker_path(device_root), b"1")
}


/// True once per relaunch that "Open as this identity" asked for: the
/// marker is consumed here so a later normal launch reads false.
pub fn take_relaunch_marker(device_root: &std::path::Path) -> bool {
    let p = relaunch_marker_path(device_root);
    if p.exists() {
        let _ = std::fs::remove_file(&p);
        true
    } else {
        false
    }
}

// ── Whose Vault is it? ────────────────────────────────────────────

static CACHE: Mutex<Vec<(u16, bool, Instant)>> = Mutex::new(Vec::new());

/// The verdict on `port` from the last minute, if there is one.
fn cached_verdict(port: u16) -> Option<bool> {
    let c = CACHE.lock().ok()?;
    c.iter().find(|(p, _, at)| *p == port && at.elapsed() < Duration::from_secs(60)).map(|(_, v, _)| *v)
}

/// True when the Vault on `port` answered within the last minute and was
/// kept as this user's.
fn checked_as_mine(port: u16) -> bool {
    cached_verdict(port) == Some(true)
}

async fn vault_is_mine(port: u16) -> bool {
    if let Some(v) = cached_verdict(port) {
        return v;
    }
    let read = tokio::task::spawn_blocking(move || listener_is_mine(port)).await.ok().flatten();
    let mine = read.unwrap_or(true);
    if let Ok(mut c) = CACHE.lock() {
        let said_before = c.iter().any(|(p, v, _)| *p == port && !*v);
        c.retain(|(p, _, _)| *p != port);
        c.push((port, mine, Instant::now()));
        if !mine && !said_before {
            log::info!("[vault] the Vault on port {port} runs as another user of this computer - ignored");
        }
    }
    mine
}

/// Some(true/false) when the owner of the process listening on `port` could
/// be read, None when it could not.
#[cfg(target_os = "linux")]
fn listener_is_mine(port: u16) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let me = std::fs::metadata("/proc/self").ok()?.uid();
    let mut seen: Option<bool> = None;
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(f) {
            for uid in proc_net_listen_uids(&text, port) {
                if uid == me {
                    return Some(true);
                }
                seen = Some(false);
            }
        }
    }
    seen
}

#[cfg(target_os = "macos")]
fn listener_is_mine(port: u16) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let me = std::fs::metadata(std::env::var_os("HOME")?).ok()?.uid();
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fu"])
        .output()
        .ok()?;
    let uids = lsof_uids(&String::from_utf8_lossy(&out.stdout));
    if uids.contains(&me) {
        return Some(true);
    }
    if !uids.is_empty() {
        return Some(false);
    }
    // Unprivileged lsof does not list other users' processes: a Vault that
    // answers on the port but is not listed runs as someone else.
    if out.status.code() == Some(1) && out.stderr.is_empty() {
        return Some(false);
    }
    None
}

#[cfg(target_os = "windows")]
fn listener_is_mine(port: u16) -> Option<bool> {
    use std::os::windows::process::CommandExt;
    const NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .creation_flags(NO_WINDOW)
        .output()
        .ok()?;
    let pid = netstat_listening_pids(&String::from_utf8_lossy(&out.stdout), &port.to_string())
        .into_iter()
        .next()?;
    let list = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/V", "/FO", "CSV", "/NH"])
        .creation_flags(NO_WINDOW)
        .output()
        .ok()?;
    let user = tasklist_user(&String::from_utf8_lossy(&list.stdout))?;
    let name = std::env::var("USERNAME").ok()?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let me_full = format!("{domain}\\{name}");
    Some(user.eq_ignore_ascii_case(&me_full) || user.eq_ignore_ascii_case(&name))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn listener_is_mine(_port: u16) -> Option<bool> {
    None
}

/// uids of the processes LISTENING on `port` in a /proc/net/tcp(6) table.
#[allow(dead_code)]
pub fn proc_net_listen_uids(text: &str, port: u16) -> Vec<u32> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() < 8 || c[3] != "0A" {
                return None; // 0A = LISTEN
            }
            let p = u16::from_str_radix(c[1].rsplit(':').next()?, 16).ok()?;
            if p != port {
                return None;
            }
            c[7].parse().ok()
        })
        .collect()
}

/// uids in `lsof -Fu` output (lines "u<uid>").
#[allow(dead_code)]
pub fn lsof_uids(text: &str) -> Vec<u32> {
    text.lines().filter_map(|l| l.strip_prefix('u')?.trim().parse().ok()).collect()
}

/// The pids LISTENING on `port` in `netstat -ano` output; a line whose
/// FOREIGN address is the port is one of our own client connections.
#[allow(dead_code)]
pub fn netstat_listening_pids(text: &str, port: &str) -> Vec<String> {
    let suffix = format!(":{port}");
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 || cols[0] != "TCP" {
                return None;
            }
            if !cols[1].ends_with(&suffix) || cols[3] != "LISTENING" {
                return None;
            }
            Some(cols[4].to_string())
        })
        .collect()
}

/// The "User Name" column of one `tasklist /V /FO CSV /NH` line.
#[allow(dead_code)]
pub fn tasklist_user(text: &str) -> Option<String> {
    let line = text.lines().find(|l| l.starts_with('"'))?;
    let cols: Vec<&str> = line.trim().trim_matches('"').split("\",\"").collect();
    cols.get(6).map(|s| s.to_string())
}

/// A stand-in Vault for tests: answers each request with what `answer`
/// gives for its method, path and query, and keeps what it was sent.
#[cfg(test)]
pub(crate) mod test_vault {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    /// One request as the stand-in received it.
    #[derive(Clone, Debug)]
    pub(crate) struct Seen {
        pub method: String,
        /// The path with its query, as sent.
        pub target: String,
        pub origin: Option<String>,
        pub body: serde_json::Value,
    }

    impl Seen {
        pub fn path(&self) -> &str {
            self.target.split('?').next().unwrap_or("")
        }
        pub fn query(&self, name: &str) -> Option<String> {
            let url = reqwest::Url::parse(&format!("http://vault{}", self.target)).ok()?;
            url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
        }
    }

    pub(crate) struct TestVault {
        pub port: u16,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl TestVault {
        pub fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }
        pub fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
        pub fn seen_on(&self, path: &str) -> Vec<Seen> {
            self.seen().into_iter().filter(|s| s.path() == path).collect()
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Option<Seen> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut lines = head.lines();
        let mut first = lines.next()?.split_whitespace();
        let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
        let header = |name: &str| {
            head.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        };
        let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        while buf.len() < head_end + length {
            let n = stream.read(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = serde_json::from_slice(&buf[head_end..]).unwrap_or(serde_json::Value::Null);
        Some(Seen { method, target, origin: header("origin"), body })
    }

    /// Start a stand-in Vault on a free port of this machine.
    pub(crate) fn start(answer: impl Fn(&Seen) -> (u16, serde_json::Value) + Send + 'static) -> TestVault {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = seen.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let Some(request) = read_request(&mut stream) else { continue };
                let (status, body) = answer(&request);
                kept.lock().unwrap().push(request);
                let body = body.to_string();
                let _ = write!(stream, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            }
        });
        TestVault { port, seen }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn client_for(vault: &test_vault::TestVault, client_id: Option<&str>) -> VaultClient {
        VaultClient::new(VaultConfig { origin: "testapp://app".into(), only_port: Some(vault.port), client_id: client_id.map(String::from) }).unwrap()
    }

    /// What a Vault from before link tokens answers on `/status`.
    fn older_status() -> serde_json::Value {
        json!({ "running": true, "unlocked": true, "initialized": true, "agent_pub_key": "uhCAkOlder", "display_name": "Ada", "profile_picture": null, "version": "1.7.0" })
    }

    #[tokio::test]
    async fn a_post_carries_the_token_and_the_client_id_once_they_are_known() {
        let vault = test_vault::start(|_| (200, json!({ "success": true })));
        let url = format!("{}/backup/list", vault.url());

        let bare = client_for(&vault, None);
        bare.post(&url, json!({ "limit": 5 })).send().await.unwrap();
        let named = client_for(&vault, Some("flowsta_app_1"));
        named.post(&url, json!({ "limit": 5 })).send().await.unwrap();
        let other = named.clone();
        named.set_link_token(Some("tok-1".into()));
        other.post(&url, json!({ "limit": 5 })).send().await.unwrap();
        other.set_link_token(None);
        named.post(&url, json!({ "limit": 5 })).send().await.unwrap();

        let seen = vault.seen();
        assert_eq!(seen[0].body, json!({ "limit": 5 }), "nothing known: nothing added");
        assert_eq!(seen[0].origin.as_deref(), Some("testapp://app"));
        assert_eq!(seen[1].body, json!({ "limit": 5, "client_id": "flowsta_app_1" }));
        assert_eq!(seen[2].body, json!({ "limit": 5, "client_id": "flowsta_app_1", "link_token": "tok-1" }), "a clone shares the token");
        assert_eq!(seen[3].body, json!({ "limit": 5, "client_id": "flowsta_app_1" }), "a forgotten token is no longer sent");
        assert!(seen.iter().all(|s| s.method == "POST" && s.target == "/backup/list"), "never in the query of a POST: {seen:?}");
    }

    #[tokio::test]
    async fn a_get_carries_the_token_and_the_client_id_once_they_are_known() {
        let vault = test_vault::start(|_| (200, json!({ "linked": true })));
        let url = format!("{}/link-status?app_agent_pub_key=uhCAkApp", vault.url());

        let client = client_for(&vault, Some("flowsta_app_1"));
        client_for(&vault, None).get(&url).send().await.unwrap();
        client.get(&url).send().await.unwrap();
        client.set_link_token(Some("tok/1+2".into()));
        client.get(&url).send().await.unwrap();

        let seen = vault.seen();
        assert_eq!(seen[0].target, "/link-status?app_agent_pub_key=uhCAkApp", "nothing known: the URL as given");
        assert_eq!((seen[1].query("client_id").as_deref(), seen[1].query("link_token")), (Some("flowsta_app_1"), None));
        assert_eq!(seen[2].query("link_token").as_deref(), Some("tok/1+2"), "{}", seen[2].target);
        assert_eq!(seen[2].query("client_id").as_deref(), Some("flowsta_app_1"));
        assert_eq!(seen[2].query("app_agent_pub_key").as_deref(), Some("uhCAkApp"), "the caller's own query is kept");
        assert!(seen.iter().all(|s| s.method == "GET" && s.body.is_null()));
    }

    #[test]
    fn only_the_routes_that_read_them_are_sent_them() {
        let both = |path| identity_fields(path, Some("c"), Some("t"));
        for route in IDENTITY_ROUTES {
            assert_eq!(both(route), vec![("link_token", "t".to_string()), ("client_id", "c".to_string())], "{route}");
        }
        assert!(both("/link-identity").is_empty(), "a new link is not asked for with the old link's token");
        assert!(both("/health").is_empty());
        assert!(both("").is_empty());
        assert_eq!(both("/backup/"), both("/backup"));
        assert!(identity_fields("/status", Some("c"), None).is_empty(), "/status says nothing until there is a token");
        assert_eq!(identity_fields("/sign", Some("c"), None), vec![("client_id", "c".to_string())]);
        assert_eq!(identity_fields("/sign", None, Some("t")), vec![("link_token", "t".to_string())]);
    }

    #[test]
    fn a_field_the_caller_set_is_kept_and_a_body_that_is_no_object_is_left_alone() {
        let client = VaultClient::new(VaultConfig { origin: "testapp://app".into(), only_port: None, client_id: Some("mine".into()) }).unwrap();
        client.set_link_token(Some("tok".into()));
        let body = |r: reqwest::RequestBuilder| serde_json::from_slice::<serde_json::Value>(r.build().unwrap().body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(body(client.post("http://127.0.0.1:27777/backup", json!({ "client_id": "theirs" }))), json!({ "client_id": "theirs", "link_token": "tok" }));
        assert_eq!(body(client.post("http://127.0.0.1:27777/backup", json!([1]))), json!([1]));
        assert_eq!(body(client.post("http://127.0.0.1:27777/link-identity", json!({ "a": 1 }))), json!({ "a": 1 }));
        client.set_link_token(Some(String::new()));
        assert_eq!(client.link_token(), None, "an empty token is no token");
        assert_eq!(client.client_id(), Some("mine"));
    }

    #[tokio::test]
    async fn status_is_asked_as_the_app_only_once_there_is_a_token() {
        let vault = test_vault::start(|_| (200, older_status()));
        let client = client_for(&vault, Some("flowsta_app_1"));

        let found = client.find(Duration::from_secs(5)).await.expect("an older Vault's status still reads");
        assert_eq!((found.port, found.unlocked, found.initialized), (vault.port, true, true));
        assert_eq!((found.agent_pub_key.as_deref(), found.display_name.as_deref(), found.profile_picture), (Some("uhCAkOlder"), Some("Ada"), None));
        assert_eq!(vault.seen().iter().map(|s| s.target.as_str()).collect::<Vec<_>>(), vec!["/status"], "no token: no query, client id or not");

        client.set_link_token(Some("tok-1".into()));
        assert_eq!(client.live_identity().await, Some((true, Some("uhCAkOlder".to_string()))));
        let last = vault.seen().pop().unwrap();
        assert_eq!((last.path(), last.query("link_token").as_deref(), last.query("client_id").as_deref()), ("/status", Some("tok-1"), Some("flowsta_app_1")));
        assert_eq!(client.base_url().await, vault.url());
    }

    #[tokio::test]
    async fn the_token_is_not_sent_to_a_port_before_its_owner_is_checked() {
        let vault = test_vault::start(|_| (200, older_status()));
        let client = client_for(&vault, None);
        client.set_link_token(Some("tok-1".into()));
        assert!(client.find(Duration::from_secs(5)).await.is_some());
        let seen = vault.seen();
        assert_eq!(seen[0].target, "/status", "first asked without the token");
        assert_eq!(seen[1].query("link_token").as_deref(), Some("tok-1"), "then with it, once the listener is known to be this user's");
        assert_eq!(seen.len(), 2);
    }

    #[tokio::test]
    async fn a_token_the_vault_refuses_does_not_hide_the_vault() {
        let vault = test_vault::start(|seen| match seen.query("link_token") {
            Some(_) => (403, json!({ "error": "invalid_link_token" })),
            None => (200, json!({ "unlocked": false, "initialized": true })),
        });
        let client = client_for(&vault, None);
        client.set_link_token(Some("old".into()));
        for _ in 0..2 {
            let found = client.find(Duration::from_secs(5)).await.expect("the Vault is there");
            assert_eq!((found.unlocked, found.agent_pub_key), (false, None));
        }
    }

    #[test]
    fn each_refusal_has_its_own_name_and_plain_words() {
        let all = [
            ("invalid_link_token", Refused::InvalidLinkToken),
            ("link_token_required", Refused::LinkTokenRequired),
            ("app_ambiguous", Refused::AppAmbiguous),
            ("origin_not_registered", Refused::OriginNotRegistered),
            ("not_addressed_here", Refused::NotAddressedHere),
        ];
        let forbidden = reqwest::StatusCode::FORBIDDEN;
        for (code, refusal) in all {
            assert_eq!(Refused::from_code(code), Some(refusal));
            assert_eq!(refusal.code(), code);
            assert_eq!(Refused::from_answer(forbidden, &json!({ "error": code, "description": "why" })), Some(refusal));
            assert_eq!(Refused::from_answer(reqwest::StatusCode::CONFLICT, &json!({ "error": code })), None, "only a 403 is one of these");
            let words = refusal.to_string();
            assert!(!words.contains('_') && words.ends_with('.'), "{words}");
        }
        let said: std::collections::HashSet<String> = all.iter().map(|(_, r)| r.to_string()).collect();
        assert_eq!(said.len(), all.len());
        assert_eq!(Refused::from_code("not_linked"), None, "an older Vault's refusals are not these");
        assert_eq!(Refused::from_answer(forbidden, &json!({ "error": "forbidden" })), None);
        assert_eq!(Refused::from_answer(forbidden, &json!(null)), None);
    }

    fn probe(port: u16, unlocked: bool, initialized: bool) -> VaultProbe {
        VaultProbe { port, url: format!("http://127.0.0.1:{port}"), unlocked, initialized, agent_pub_key: None, display_name: None, profile_picture: None }
    }

    #[test]
    fn unlocked_beats_locked_beats_fresh_and_lower_port_breaks_ties() {
        let a = [probe(27777, false, true), probe(27778, true, true)];
        assert_eq!(pick_vault(&a).unwrap().port, 27778);
        let b = [probe(27777, false, false), probe(27779, false, true)];
        assert_eq!(pick_vault(&b).unwrap().port, 27779);
        let c = [probe(27777, true, true), probe(27778, true, true)];
        assert_eq!(pick_vault(&c).unwrap().port, 27777);
        assert!(pick_vault(&[]).is_none());
    }

    #[test]
    fn proc_net_names_the_listener_uid_for_the_port() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:6C81 00000000:0000 0A 00000000:00000000 00:00000000 00000000   501        0 11111 1
   1: 0100007F:6C82 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1
   2: 0100007F:D1F4 0100007F:6C81 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1
";
        assert_eq!(proc_net_listen_uids(text, 27777), vec![501]);
        assert_eq!(proc_net_listen_uids(text, 27778), vec![1000]);
        assert!(proc_net_listen_uids(text, 27779).is_empty());
    }

    #[test]
    fn lsof_netstat_and_tasklist_parsers() {
        assert_eq!(lsof_uids("p123\nu501\nf12\nu502\n"), vec![501, 502]);
        let ns = "  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:27777        0.0.0.0:0              LISTENING       4242
  TCP    127.0.0.1:53012        127.0.0.1:27777        ESTABLISHED     999
";
        assert_eq!(netstat_listening_pids(ns, "27777"), vec!["4242"]);
        let tl = "\"flowsta-vault.exe\",\"4242\",\"Console\",\"1\",\"12,345 K\",\"Running\",\"PC\\eric\",\"0:00:01\",\"Flowsta Vault\"\n";
        assert_eq!(tasklist_user(tl).as_deref(), Some("PC\\eric"));
    }
}
