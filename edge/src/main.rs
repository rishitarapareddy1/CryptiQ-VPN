//! CryptiQ edge peer for local / staging / production use.
//!
//! Serves the hybrid ML-KEM-768 + X25519 handshake, derives a WireGuard
//! PresharedKey from the session, registers each client's WireGuard public
//! key, and writes a server-side WireGuard config.
//!
//! Peers + PSKs persist across restarts in `$CRYPTIQ_EDGE_STATE_DIR/peers.json`.
//!
//! Run:  cargo run --manifest-path edge/Cargo.toml
//! Bind: http://127.0.0.1:8787

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ct = Ciphertext<MlKem768>;

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    server_wg_private_b64: String,
    server_wg_public_b64: String,
    wg_endpoint: String,
    dns: String,
    state_dir: PathBuf,
    /// Outbound interface for NAT (e.g. eth0 / ens3). When set, the generated
    /// server config masquerades client traffic so full-tunnel clients reach
    /// the internet.
    nat_iface: Option<String>,
    /// Pending handshakes keyed by id.
    pending: HashMap<String, Pending>,
    /// Registered peers: wg public key → (assigned VPN IP, ML-KEM-derived PSK).
    peers: HashMap<String, PeerEntry>,
    next_host: u8,
}

#[derive(Clone, Serialize, Deserialize)]
struct PeerEntry {
    vpn_ip: String,
    psk_b64: String,
}

#[derive(Serialize, Deserialize)]
struct PersistedPeers {
    next_host: u8,
    peers: HashMap<String, PeerEntry>,
}

struct Pending {
    dk: Dk,
    x_secret: StaticSecret,
}

#[derive(Serialize)]
struct Hello {
    handshake_id: String,
    kem_public_key_b64: String,
    server_x25519_pub_b64: String,
    server_wg_pub_b64: String,
    wg_endpoint: String,
}

#[derive(Deserialize)]
struct FinishReq {
    handshake_id: String,
    kem_ciphertext_b64: String,
    client_x25519_pub_b64: String,
    client_wg_pub_b64: String,
}

#[derive(Serialize)]
struct FinishRes {
    ok: bool,
    session_fingerprint: String,
    client_vpn_ip: String,
    server_vpn_ip: String,
    dns: Option<String>,
}

fn hybrid_kdf(ss_pq: &[u8], ss_x25519: &[u8]) -> [u8; 32] {
    let mut kdf = Sha256::new();
    kdf.update(b"cryptiq-personal-hybrid-v1");
    kdf.update(ss_pq);
    kdf.update(ss_x25519);
    let out = kdf.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn fingerprint(key: &[u8; 32]) -> String {
    key[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Same derivation as the client's `pqc::derive_wg_psk`: mixing this into
/// WireGuard's key schedule makes the data plane require breaking ML-KEM-768
/// on top of Curve25519.
fn derive_wg_psk(session_key: &[u8; 32]) -> String {
    let mut kdf = Sha256::new();
    kdf.update(b"cryptiq-wg-psk-v1");
    kdf.update(session_key);
    B64.encode(kdf.finalize())
}

fn wg_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (B64.encode(secret.to_bytes()), B64.encode(public.as_bytes()))
}

fn peers_path(state_dir: &Path) -> PathBuf {
    state_dir.join("peers.json")
}

fn load_peers(state_dir: &Path) -> PersistedPeers {
    let path = peers_path(state_dir);
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
            eprintln!("warning: could not parse {}: {e}", path.display());
            PersistedPeers {
                next_host: 1,
                peers: HashMap::new(),
            }
        }),
        Err(_) => PersistedPeers {
            next_host: 1,
            peers: HashMap::new(),
        },
    }
}

fn save_peers(g: &Inner) -> Result<(), String> {
    let persisted = PersistedPeers {
        next_host: g.next_host,
        peers: g.peers.clone(),
    };
    let path = peers_path(&g.state_dir);
    let raw = serde_json::to_string_pretty(&persisted).map_err(|e| e.to_string())?;
    std::fs::write(&path, raw).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Best-effort live reload of the WireGuard interface so new peers/PSKs take
/// effect without waiting for the cron/timer. No-op if the interface is down.
fn try_sync_wg_interface(conf: &Path) {
    // Prefer the host helper installed by our deploy script.
    if Path::new("/usr/local/bin/cryptiq-wg-sync").exists() {
        let _ = Command::new("/usr/local/bin/cryptiq-wg-sync").status();
        return;
    }
    // Fallback: if the interface is already up, strip + syncconf.
    let iface = "wg-cryptiq";
    let check = Command::new("ip")
        .args(["link", "show", iface])
        .output();
    if !matches!(check, Ok(o) if o.status.success()) {
        return;
    }
    let strip = Command::new("wg-quick").args(["strip", iface]).output();
    if let Ok(stripped) = strip {
        if stripped.status.success() {
            let mut child = match Command::new("wg")
                .args(["syncconf", iface, "/dev/stdin"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(_) => return,
            };
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(&stripped.stdout);
            }
            let _ = child.wait();
            let _ = conf; // conf path retained for logging callers
        }
    }
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let g = state.inner.lock();
    Json(serde_json::json!({
        "ok": true,
        "service": "cryptiq-edge",
        "version": "0.6.0",
        "peers": g.peers.len(),
        "pq_data_plane": true,
    }))
}

async fn handshake_start(State(state): State<AppState>) -> impl IntoResponse {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x_pub = PublicKey::from(&x_secret);
    let id = Uuid::new_v4().to_string();

    let hello = {
        let mut g = state.inner.lock();
        let ek_b64 = B64.encode(ek.as_bytes().as_slice());
        let x_pub_b64 = B64.encode(x_pub.as_bytes());
        g.pending.insert(
            id.clone(),
            Pending {
                dk,
                x_secret,
            },
        );
        Hello {
            handshake_id: id,
            kem_public_key_b64: ek_b64,
            server_x25519_pub_b64: x_pub_b64,
            server_wg_pub_b64: g.server_wg_public_b64.clone(),
            wg_endpoint: g.wg_endpoint.clone(),
        }
    };
    Json(hello)
}

async fn handshake_finish(
    State(state): State<AppState>,
    Json(req): Json<FinishReq>,
) -> Result<Json<FinishRes>, (StatusCode, String)> {
    let pending = {
        let mut g = state.inner.lock();
        g.pending
            .remove(&req.handshake_id)
            .ok_or((StatusCode::BAD_REQUEST, "unknown handshake_id".into()))?
    };

    let ct_bytes = B64
        .decode(&req.kem_ciphertext_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad ciphertext: {e}")))?;
    let ct = Ct::try_from(ct_bytes.as_slice())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid ciphertext length".into()))?;
    let ss_pq = pending
        .dk
        .decapsulate(&ct)
        .map_err(|_| (StatusCode::BAD_REQUEST, "decapsulation failed".into()))?;

    let client_x_bytes = B64
        .decode(&req.client_x25519_pub_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad client x25519: {e}")))?;
    if client_x_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "client x25519 must be 32 bytes".into()));
    }
    let mut cx = [0u8; 32];
    cx.copy_from_slice(&client_x_bytes);
    let ss_x = pending.x_secret.diffie_hellman(&PublicKey::from(cx));
    let session_key = hybrid_kdf(ss_pq.as_slice(), ss_x.as_bytes());
    let fp = fingerprint(&session_key);

    let psk = derive_wg_psk(&session_key);
    let (client_ip, conf_path) = {
        let mut g = state.inner.lock();
        let ip = if let Some(existing) = g.peers.get(&req.client_wg_pub_b64) {
            existing.vpn_ip.clone()
        } else {
            if g.next_host >= 250 {
                return Err((StatusCode::SERVICE_UNAVAILABLE, "peer pool exhausted".into()));
            }
            g.next_host += 1;
            format!("10.66.66.{}", g.next_host)
        };
        // Fresh handshake ⇒ fresh PSK: always upsert so the server side
        // matches the key the client just derived.
        g.peers.insert(
            req.client_wg_pub_b64.clone(),
            PeerEntry {
                vpn_ip: ip.clone(),
                psk_b64: psk.clone(),
            },
        );
        rewrite_server_conf(&g).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        save_peers(&g).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let conf = g.state_dir.join("wg-cryptiq.conf");
        (ip, conf)
    };
    // Live-reload outside the lock so we don't block other handshakes.
    try_sync_wg_interface(&conf_path);

    let dns = state.inner.lock().dns.clone();
    Ok(Json(FinishRes {
        ok: true,
        session_fingerprint: fp,
        client_vpn_ip: client_ip,
        server_vpn_ip: "10.66.66.1".into(),
        dns: Some(dns),
    }))
}

fn rewrite_server_conf(g: &Inner) -> Result<(), String> {
    let path = g.state_dir.join("wg-cryptiq.conf");
    // NAT rules let full-tunnel clients (AllowedIPs 0.0.0.0/0) reach the
    // internet through this box. Linux-only; harmless to omit for local dev.
    // Insert (-I ... 1) rather than append: cloud images (Oracle, etc.) often
    // ship a catch-all REJECT at the end of FORWARD, and an appended ACCEPT
    // would never be reached since iptables stops at the first match.
    let nat = g
        .nat_iface
        .as_deref()
        .map(|iface| {
            format!(
                "PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT; \
                 iptables -I FORWARD 1 -o %i -j ACCEPT; \
                 iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n\
                 PostDown = iptables -D FORWARD -i %i -j ACCEPT; \
                 iptables -D FORWARD -o %i -j ACCEPT; \
                 iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n"
            )
        })
        .unwrap_or_default();
    let mut body = format!(
        "# CryptiQ edge WireGuard config — regenerated on each peer join\n\
         # Bring up with: sudo wg-quick up {}\n\
         [Interface]\n\
         PrivateKey = {}\n\
         Address = 10.66.66.1/24\n\
         ListenPort = 51820\n\
         {nat}\n",
        path.display(),
        g.server_wg_private_b64
    );
    for (pub_key, peer) in &g.peers {
        body.push_str(&format!(
            "[Peer]\nPublicKey = {pub_key}\nPresharedKey = {}\nAllowedIPs = {}/32\n\n",
            peer.psk_b64, peer.vpn_ip
        ));
    }
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    println!("wrote {} ({} peers)", path.display(), g.peers.len());
    Ok(())
}

/// Load the WireGuard keypair from disk, or generate and persist one.
/// A stable key is required in production: clients cache the server public
/// key in their configs, and a restart must not invalidate them.
fn load_or_create_wg_keypair(state_dir: &PathBuf) -> (String, String) {
    let key_path = state_dir.join("wg-server.key");
    if let Ok(existing) = std::fs::read_to_string(&key_path) {
        let priv_b64 = existing.trim().to_string();
        if let Ok(bytes) = B64.decode(&priv_b64) {
            if bytes.len() == 32 {
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&bytes);
                let secret = StaticSecret::from(sk);
                let public = PublicKey::from(&secret);
                return (priv_b64, B64.encode(public.as_bytes()));
            }
        }
        eprintln!("warning: {} is corrupt, generating a new key", key_path.display());
    }
    let (priv_b64, pub_b64) = wg_keypair();
    if let Err(e) = std::fs::write(&key_path, &priv_b64) {
        eprintln!("warning: could not persist server key: {e}");
    }
    (priv_b64, pub_b64)
}

#[tokio::main]
async fn main() {
    let state_dir = std::env::var("CRYPTIQ_EDGE_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    std::fs::create_dir_all(&state_dir).expect("create state dir");

    let (priv_b64, pub_b64) = load_or_create_wg_keypair(&state_dir);
    let endpoint = std::env::var("CRYPTIQ_WG_ENDPOINT").unwrap_or_else(|_| "127.0.0.1:51820".into());
    let bind = std::env::var("CRYPTIQ_EDGE_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let dns = std::env::var("CRYPTIQ_EDGE_DNS").unwrap_or_else(|_| "1.1.1.1".into());
    let nat_iface = std::env::var("CRYPTIQ_NAT_IFACE").ok().filter(|s| !s.is_empty());

    let persisted = load_peers(&state_dir);
    println!(
        "loaded {} persisted peer(s); next_host={}",
        persisted.peers.len(),
        persisted.next_host
    );

    let state = AppState {
        inner: Arc::new(Mutex::new(Inner {
            server_wg_private_b64: priv_b64,
            server_wg_public_b64: pub_b64.clone(),
            wg_endpoint: endpoint.clone(),
            dns,
            state_dir,
            nat_iface,
            pending: HashMap::new(),
            peers: persisted.peers,
            next_host: persisted.next_host.max(1),
        })),
    };

    // Rewrite conf from persisted peers so a restart doesn't wipe PSKs.
    {
        let g = state.inner.lock();
        rewrite_server_conf(&g).expect("write initial wg conf");
    }
    try_sync_wg_interface(&state.inner.lock().state_dir.join("wg-cryptiq.conf"));

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/handshake/start", get(handshake_start))
        .route("/v1/handshake/finish", post(handshake_finish))
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    let addr: SocketAddr = bind.parse().expect("bad CRYPTIQ_EDGE_BIND");
    let conf_hint = state.inner.lock().state_dir.join("wg-cryptiq.conf");
    println!("cryptiq-edge listening on http://{addr}");
    println!("WireGuard public key: {pub_b64}");
    println!("WireGuard endpoint:   {endpoint}");
    println!("Bring up WG with:     sudo wg-quick up {}", conf_hint.display());

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
