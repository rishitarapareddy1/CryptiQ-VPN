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
        if let Some(conf) = g.active_conf.take() {
            let _ = run_wg_quick("down", &conf);
            let _ = std::fs::remove_file(&conf);
        }
        g.status = TunnelStatus {
            edge_url: g.status.edge_url.clone(),
            ..TunnelStatus::default()
        };
        Ok(g.status.clone())
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
        let conf = render_wg_conf(
            &wg.private_b64,
            &finish.client_vpn_ip,
            &hello.server_wg_pub_b64,
            &hello.wg_endpoint,
            &allowed_ips,
            dns.as_deref(),
        );
        std::fs::write(&conf_path, &conf).map_err(|e| e.to_string())?;

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
) -> String {
    let dns_line = dns
        .map(|d| format!("DNS = {d}\n"))
        .unwrap_or_default();
    format!(
        "# CryptiQ Personal — generated after ML-KEM-768 + X25519 handshake\n\
         # Do not share this file; it contains your WireGuard private key.\n\
         [Interface]\n\
         PrivateKey = {private_b64}\n\
         Address = {client_ip}/32\n\
         {dns_line}\
         [Peer]\n\
         PublicKey = {server_pub_b64}\n\
         Endpoint = {endpoint}\n\
         AllowedIPs = {allowed_ips}\n\
         PersistentKeepalive = 25\n"
    )
}

fn run_wg_quick(action: &str, conf: &Path) -> Result<(), String> {
    // Prefer Homebrew path; fall back to PATH.
    let wg_quick = [
        "/opt/homebrew/bin/wg-quick",
        "/usr/local/bin/wg-quick",
        "wg-quick",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists() || *p == "wg-quick")
    .unwrap_or("wg-quick");

    // macOS ships bash 3 at /bin/bash; Homebrew wg-quick needs bash 4+.
    let bash = ["/opt/homebrew/bin/bash", "/usr/local/bin/bash", "bash"]
        .into_iter()
        .find(|p| *p == "bash" || Path::new(p).exists())
        .unwrap_or("bash");

    // Copy to a name wg-quick accepts as an interface name (no path weirdness).
    // On macOS, wg-quick expects the interface name from the filename stem.
    let iface_conf = conf
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{IFACE}.conf"));
    if conf != iface_conf {
        std::fs::copy(conf, &iface_conf).map_err(|e| e.to_string())?;
    }

    let out = Command::new(bash)
        .arg(wg_quick)
        .arg(action)
        .arg(&iface_conf)
        .output()
        .map_err(|e| {
            format!(
                "could not run wg-quick ({e}). Install with: brew install wireguard-tools"
            )
        })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {}",
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        )
        .trim()
        .to_string())
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
    let conf = render_wg_conf(
        &wg.private_b64,
        "10.66.66.2",
        &server_wg.public_b64,
        "127.0.0.1:51820",
        "10.66.66.1/32",
        Some("1.1.1.1"),
    );
    assert!(conf.contains("PrivateKey ="));
    assert!(conf.contains("[Peer]"));
    Ok((pqc::to_handshake_result(&secrets), conf))
}
