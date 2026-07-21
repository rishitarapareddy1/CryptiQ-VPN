//! Tunnel manager: hybrid PQ handshake with a CryptiQ edge, then WireGuard.
//!
//! Flow:
//! 1. GET  {edge}/v1/handshake/start
//! 2. Local ML-KEM + X25519 finish → session fingerprint
//! 3. POST {edge}/v1/handshake/finish with client WireGuard public key
//! 4. Write wg0.conf and attempt `wg-quick up`
//!
//! On macOS, bringing the interface up usually needs admin rights. If that
//! fails we still leave a valid config the user can import into the WireGuard
//! app — handshake + peer exchange already happened over the PQ channel.

use crate::pqc::{self, EdgeFinishResponse, EdgeHello, HandshakeResult};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

const DEFAULT_EDGE: &str = "http://64.181.224.148:8787";
const IFACE: &str = "utuncryptiq";

#[derive(Serialize, Clone, Debug)]
pub struct TunnelStatus {
    pub state: String, // "down" | "handshaking" | "up" | "config_ready"
    pub handshake: Option<HandshakeResult>,
    pub edge_url: String,
    pub config_path: Option<String>,
    pub client_vpn_ip: Option<String>,
    pub endpoint: Option<String>,
    pub message: String,
    pub transport: String, // "wireguard" | "handshake_only"
    pub routing: String,   // "peer_only" | "full_tunnel"
    /// Fingerprint of the ML-KEM-derived WireGuard PresharedKey (proof the
    /// data plane is PQ-hardened; never the key itself).
    pub psk_fingerprint: Option<String>,
}

pub struct TunnelManager {
    inner: Mutex<TunnelInner>,
}

struct TunnelInner {
    status: TunnelStatus,
    /// Path we brought up, if any — used for disconnect.
    active_conf: Option<PathBuf>,
}

impl Default for TunnelStatus {
    fn default() -> Self {
        Self {
            state: "down".into(),
            handshake: None,
            edge_url: DEFAULT_EDGE.into(),
            config_path: None,
            client_vpn_ip: None,
            endpoint: None,
            message: "Tunnel idle".into(),
            transport: "handshake_only".into(),
            routing: "peer_only".into(),
            psk_fingerprint: None,
        }
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TunnelInner {
                status: TunnelStatus::default(),
                active_conf: None,
            }),
        }
    }

    pub fn status(&self) -> TunnelStatus {
        self.inner.lock().unwrap().status.clone()
    }

    pub fn disconnect(&self) -> Result<TunnelStatus, String> {
        let mut g = self.inner.lock().unwrap();
        // Prefer the conf we brought up; fall back to the written path so
        // config_ready sessions can still tear down if the user brought WG up manually.
        let conf = g.active_conf.take().or_else(|| {
            g.status
                .config_path
                .as_ref()
                .map(PathBuf::from)
        });
        if let Some(conf) = conf {
            let _ = run_wg_quick("down", &conf);
            let iface_conf = conf
                .parent()
                .unwrap_or(Path::new("."))
                .join(format!("{IFACE}.conf"));
            let _ = std::fs::remove_file(&iface_conf);
        }
        g.status = TunnelStatus {
            edge_url: g.status.edge_url.clone(),
            ..TunnelStatus::default()
        };
        Ok(g.status.clone())
    }

    /// Retry `wg-quick up` on an existing config_ready session (shows the
    /// macOS admin password dialog). No-op if already up.
    pub fn bring_up(&self) -> Result<TunnelStatus, String> {
        let conf_path = {
            let g = self.inner.lock().unwrap();
            if g.status.state == "up" {
                return Ok(g.status.clone());
            }
            g.status
                .config_path
                .clone()
                .ok_or_else(|| "no WireGuard config ready — connect first".to_string())?
        };
        let path = PathBuf::from(&conf_path);
        match run_wg_quick("up", &path) {
            Ok(()) => {
                let mut g = self.inner.lock().unwrap();
                g.active_conf = Some(path);
                g.status.state = "up".into();
                g.status.transport = "wireguard".into();
                g.status.message = format!(
                    "Tunnel up — traffic via ML-KEM-768 PSK + WireGuard ({})",
                    g.status
                        .handshake
                        .as_ref()
                        .map(|h| h.session_fingerprint.clone())
                        .unwrap_or_default()
                );
                Ok(g.status.clone())
            }
            Err(e) => Err(e),
        }
    }

    pub fn connect(&self, edge_url: Option<String>, full_tunnel: bool) -> Result<TunnelStatus, String> {
        let edge = edge_url
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_EDGE.to_string());

        {
            let mut g = self.inner.lock().unwrap();
            if g.status.state == "up" || g.status.state == "config_ready" {
                return Err("tunnel already connected — disconnect first".into());
            }
            g.status.state = "handshaking".into();
            g.status.edge_url = edge.clone();
            g.status.message = format!("Negotiating hybrid handshake with {edge}");
        }

        let result = self.connect_inner(&edge, full_tunnel);
        let mut g = self.inner.lock().unwrap();
        match result {
            Ok((status, active)) => {
                g.active_conf = active;
                g.status = status;
                Ok(g.status.clone())
            }
            Err(e) => {
                g.status = TunnelStatus {
                    state: "down".into(),
                    edge_url: edge,
                    message: e.clone(),
                    ..TunnelStatus::default()
                };
                Err(e)
            }
        }
    }

    fn connect_inner(
        &self,
        edge: &str,
        full_tunnel: bool,
    ) -> Result<(TunnelStatus, Option<PathBuf>), String> {
        let wg = generate_wg_keypair();

        let hello: EdgeHello = ureq::get(&format!("{edge}/v1/handshake/start"))
            .call()
            .map_err(|e| format!("edge unreachable at {edge}: {e}"))?
            .into_json()
            .map_err(|e| format!("bad hello from edge: {e}"))?;

        let (secrets, finish_req) = pqc::client_finish(&hello, &wg.public_b64)?;
        let finish: EdgeFinishResponse = ureq::post(&format!("{edge}/v1/handshake/finish"))
            .send_json(&finish_req)
            .map_err(|e| format!("edge finish failed: {e}"))?
            .into_json()
            .map_err(|e| format!("bad finish from edge: {e}"))?;

        if !finish.ok {
            return Err("edge rejected handshake".into());
        }
        if finish.session_fingerprint != secrets.fingerprint {
            return Err(format!(
                "session fingerprint mismatch (client {} vs edge {})",
                secrets.fingerprint, finish.session_fingerprint
            ));
        }

        let conf_path = conf_dir()?.join("cryptiq0.conf");
        let allowed_ips = if full_tunnel {
            // Route everything through the edge. DNS pinned so lookups also
            // traverse the tunnel (prevents DNS leaks).
            "0.0.0.0/0, ::/0".to_string()
        } else {
            format!("{}/32", finish.server_vpn_ip)
        };
        // Full tunnel needs DNS pinned inside the tunnel; fall back to the
        // edge's VPN IP if it didn't advertise a resolver.
        let dns = finish
            .dns
            .clone()
            .or_else(|| full_tunnel.then(|| finish.server_vpn_ip.clone()));
        // Mix the ML-KEM-derived key into WireGuard's key schedule: with the
        // PSK set on both sides, the data plane is quantum-resistant too.
        let psk = pqc::derive_wg_psk(&secrets.session_key);
        let conf = render_wg_conf(
            &wg.private_b64,
            &finish.client_vpn_ip,
            &hello.server_wg_pub_b64,
            &hello.wg_endpoint,
            &allowed_ips,
            dns.as_deref(),
            Some(&psk),
        );
        std::fs::write(&conf_path, &conf).map_err(|e| e.to_string())?;
        // Config holds the WG private key + PSK; owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o600));
        }

        let handshake = pqc::to_handshake_result(&secrets);
        let mut status = TunnelStatus {
            state: "config_ready".into(),
            handshake: Some(handshake),
            edge_url: edge.into(),
            config_path: Some(conf_path.display().to_string()),
            client_vpn_ip: Some(finish.client_vpn_ip.clone()),
            endpoint: Some(hello.wg_endpoint.clone()),
            message: format!(
                "PQ handshake OK ({}). Config written to {}.",
                secrets.fingerprint,
                conf_path.display()
            ),
            transport: "handshake_only".into(),
            routing: if full_tunnel { "full_tunnel" } else { "peer_only" }.into(),
            psk_fingerprint: Some(pqc::psk_fingerprint(&psk)),
        };

        // Try to bring the interface up. Failure is non-fatal — config is still valid.
        match run_wg_quick("up", &conf_path) {
            Ok(()) => {
                status.state = "up".into();
                status.transport = "wireguard".into();
                status.message = format!(
                    "Tunnel up — traffic to {} via ML-KEM-768 + WireGuard ({})",
                    finish.client_vpn_ip, secrets.fingerprint
                );
                Ok((status, Some(conf_path)))
            }
            Err(e) => {
                status.message = format!(
                    "PQ handshake OK and config ready at {}. \
                     WireGuard interface not brought up automatically ({e}). \
                     Import the config into the WireGuard app, or run: sudo wg-quick up '{}'",
                    conf_path.display(),
                    conf_path.display()
                );
                Ok((status, None))
            }
        }
    }
}

struct WgKeypair {
    private_b64: String,
    public_b64: String,
}

fn generate_wg_keypair() -> WgKeypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    WgKeypair {
        private_b64: B64.encode(secret.to_bytes()),
        public_b64: B64.encode(public.as_bytes()),
    }
}

fn conf_dir() -> Result<PathBuf, String> {
    if let Ok(custom) = std::env::var("CRYPTIQ_WG_DIR") {
        let dir = PathBuf::from(custom);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        return Ok(dir);
    }
    let dir = dirs::data_dir()
        .ok_or("no data directory")?
        .join("CryptiQ Personal")
        .join("wireguard");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

pub fn render_wg_conf(
    private_b64: &str,
    client_ip: &str,
    server_pub_b64: &str,
    endpoint: &str,
    allowed_ips: &str,
    dns: Option<&str>,
    preshared_key_b64: Option<&str>,
) -> String {
    let dns_line = dns
        .map(|d| format!("DNS = {d}\n"))
        .unwrap_or_default();
    let psk_line = preshared_key_b64
        .map(|k| format!("PresharedKey = {k}\n"))
        .unwrap_or_default();
    format!(
        "# CryptiQ Personal — generated after ML-KEM-768 + X25519 handshake\n\
         # The PresharedKey below is derived from the ML-KEM-768 shared secret,\n\
         # making the WireGuard data plane quantum-resistant as well.\n\
         # Do not share this file; it contains your WireGuard private key.\n\
         [Interface]\n\
         PrivateKey = {private_b64}\n\
         Address = {client_ip}/32\n\
         {dns_line}\
         [Peer]\n\
         PublicKey = {server_pub_b64}\n\
         {psk_line}\
         Endpoint = {endpoint}\n\
         AllowedIPs = {allowed_ips}\n\
         PersistentKeepalive = 25\n"
    )
}

/// The app's own `resources/wireguard/` — bundled wg, wg-quick, wireguard-go,
/// and a self-contained bash 4+ (with its Homebrew dylib deps re-pointed at
/// `@executable_path/lib/` and re-signed; see resources/wireguard/THIRD_PARTY_NOTICES.md).
/// This is what makes the tunnel work on a machine with no Homebrew at all.
/// Only resolvable inside a real bundled .app — `current_exe()` under `cargo
/// run` sits in target/debug/, which has no such directory, so dev builds
/// fall through to the Homebrew/system search below unchanged.
fn bundled_wireguard_dir() -> Option<PathBuf> {
    let dir = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .join("Resources")
        .join("resources")
        .join("wireguard");
    dir.join("wg-quick").exists().then_some(dir)
}

fn run_wg_quick(action: &str, conf: &Path) -> Result<(), String> {
    let bundled = bundled_wireguard_dir();

    // wg-quick must exist; without wireguard-tools (bundled or Homebrew)
    // there is nothing to escalate to.
    let wg_quick: PathBuf = match &bundled {
        Some(dir) => dir.join("wg-quick"),
        None => ["/opt/homebrew/bin/wg-quick", "/usr/local/bin/wg-quick"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
            .ok_or("WireGuard tools not installed. Install with: brew install wireguard-tools")?,
    };

    // macOS ships bash 3 at /bin/bash; wg-quick needs bash 4+ (associative
    // arrays). Bundled bash is self-contained; Homebrew's is the dev fallback.
    let bash: PathBuf = match &bundled {
        Some(dir) => dir.join("bash"),
        None => ["/opt/homebrew/bin/bash", "/usr/local/bin/bash"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
            .unwrap_or_else(|| PathBuf::from("/bin/bash")),
    };

    // wg-quick shells out to bare `wg` and `wireguard-go` by name — put
    // whichever directory we resolved above first on PATH so it finds our
    // copies (bundled or Homebrew) instead of requiring a system install.
    let path_prefix = bundled
        .as_ref()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "/opt/homebrew/bin:/usr/local/bin".to_string());

    // Copy to a name wg-quick accepts as an interface name (no path weirdness).
    // On macOS, wg-quick expects the interface name from the filename stem.
    let iface_conf = conf
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{IFACE}.conf"));
    if conf != iface_conf {
        std::fs::copy(conf, &iface_conf).map_err(|e| e.to_string())?;
    }

    // First try without escalation (works when already root, e.g. CLI/tests
    // run under sudo). wg-quick needs root, so from the GUI this will fail.
    let system_path = std::env::var("PATH").unwrap_or_default();
    let direct = Command::new(&bash)
        .arg(&wg_quick)
        .arg(action)
        .arg(&iface_conf)
        .env("PATH", format!("{path_prefix}:{system_path}"))
        .output();
    if let Ok(o) = &direct {
        if o.status.success() {
            return Ok(());
        }
    }

    // Escalate through the native macOS admin-password dialog. This is the
    // path a GUI app is supposed to use — no terminal, no silent sudo failure.
    let shell_cmd = format!(
        "PATH={path_prefix}:/usr/bin:/bin:/usr/sbin:/sbin '{}' '{}' {action} '{}'",
        bash.display(),
        wg_quick.display(),
        iface_conf.display()
    );
    let verb = if action == "up" { "start" } else { "stop" };
    let script = format!(
        "do shell script \"{}\" with administrator privileges with prompt \"CryptiQ Personal wants to {verb} the quantum-safe tunnel.\"",
        shell_cmd.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let out = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| format!("could not run osascript: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if err.contains("User canceled") || err.contains("-128") {
            Err("Administrator authorization was declined — tunnel config is ready but the interface was not brought up.".into())
        } else {
            Err(err)
        }
    }
}

/// In-process round-trip used by tests (no HTTP, no wg-quick).
pub fn simulate_peer_exchange() -> Result<(HandshakeResult, String), String> {
    let wg = generate_wg_keypair();
    let server_wg = generate_wg_keypair();
    let session = pqc::server_start(
        "test-hs".into(),
        server_wg.public_b64.clone(),
        "127.0.0.1:51820".into(),
    );
    let hello = session.hello();
    let (secrets, req) = pqc::client_finish(&hello, &wg.public_b64)?;
    let server_secrets = session.finish(&req)?;
    if secrets.fingerprint != server_secrets.fingerprint {
        return Err("fingerprint mismatch in simulated exchange".into());
    }
    let psk = pqc::derive_wg_psk(&secrets.session_key);
    let server_psk = pqc::derive_wg_psk(&server_secrets.session_key);
    if psk != server_psk {
        return Err("PSK derivation mismatch between peers".into());
    }
    let conf = render_wg_conf(
        &wg.private_b64,
        "10.66.66.2",
        &server_wg.public_b64,
        "127.0.0.1:51820",
        "10.66.66.1/32",
        Some("1.1.1.1"),
        Some(&psk),
    );
    assert!(conf.contains("PrivateKey ="));
    assert!(conf.contains("PresharedKey ="));
    assert!(conf.contains("[Peer]"));
    Ok((pqc::to_handshake_result(&secrets), conf))
}
