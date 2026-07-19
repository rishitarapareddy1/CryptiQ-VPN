//! Hybrid post-quantum handshake: ML-KEM-768 (FIPS 203) + X25519.
//!
//! Two modes:
//! - `hybrid_handshake()` — both sides in-process (tests / offline demo)
//! - `client_finish` / `ServerSession` — networked handshake with a CryptiQ edge node
//!
//! The derived session key does two jobs: it authenticates the WireGuard peer
//! exchange, and (via `derive_wg_psk`) it becomes the WireGuard PresharedKey
//! that both sides mix into the data-plane key schedule. Because WireGuard
//! folds the PSK into every session key it derives, breaking the tunnel
//! requires breaking ML-KEM-768 in addition to Curve25519 — the data plane
//! inherits the post-quantum security of the handshake.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ct = Ciphertext<MlKem768>;

#[derive(Serialize, Clone, Debug)]
pub struct HandshakeResult {
    pub kem: String,
    pub classical: String,
    pub kdf: String,
    pub session_fingerprint: String,
    pub kem_ciphertext_preview: String,
    pub kem_ciphertext_bytes: usize,
    pub kem_encaps_key_bytes: usize,
    pub kem_shared_secret_bytes: usize,
    pub classical_shared_secret_bytes: usize,
    pub kdf_label: String,
    pub duration_ms: f64,
}

/// Raw material both peers share after a successful handshake.
#[derive(Clone)]
pub struct SessionSecrets {
    pub session_key: [u8; 32],
    pub fingerprint: String,
    pub kem_ciphertext_preview: String,
    pub kem_ciphertext_bytes: usize,
    pub kem_encaps_key_bytes: usize,
    pub duration_ms: f64,
}

fn fingerprint(key: &[u8; 32]) -> String {
    key[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
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

/// Derive the WireGuard PresharedKey from the hybrid session key.
///
/// WireGuard mixes the PSK into its own key schedule, so with this in place
/// an attacker must break ML-KEM-768 *in addition to* Curve25519 to decrypt
/// the data plane — the tunnel itself becomes quantum-resistant, not just
/// the peer exchange. Domain-separated from the session key by the label.
pub fn derive_wg_psk(session_key: &[u8; 32]) -> String {
    let mut kdf = Sha256::new();
    kdf.update(b"cryptiq-wg-psk-v1");
    kdf.update(session_key);
    B64.encode(kdf.finalize())
}

/// Short hex fingerprint of a derived PSK (for display, never the key itself).
pub fn psk_fingerprint(psk_b64: &str) -> String {
    let mut h = Sha256::new();
    h.update(psk_b64.as_bytes());
    h.finalize()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn encode_fixed(bytes: &[u8]) -> Result<Encoded<Ek>, String> {
    Encoded::<Ek>::try_from(bytes).map_err(|_| "invalid ML-KEM encapsulation key length".into())
}

fn encode_ct(bytes: &[u8]) -> Result<Ct, String> {
    Ct::try_from(bytes).map_err(|_| "invalid ML-KEM ciphertext length".into())
}

pub fn to_handshake_result(s: &SessionSecrets) -> HandshakeResult {
    HandshakeResult {
        kem: "ML-KEM-768".into(),
        classical: "X25519".into(),
        kdf: "SHA-256 hybrid".into(),
        session_fingerprint: s.fingerprint.clone(),
        kem_ciphertext_preview: s.kem_ciphertext_preview.clone(),
        kem_ciphertext_bytes: s.kem_ciphertext_bytes,
        kem_encaps_key_bytes: s.kem_encaps_key_bytes,
        kem_shared_secret_bytes: 32,
        classical_shared_secret_bytes: 32,
        kdf_label: "cryptiq-personal-hybrid-v1".into(),
        duration_ms: s.duration_ms,
    }
}

/// Offline both-sides handshake (kept for tests and the Technical tab demo path).
pub fn hybrid_handshake() -> Result<HandshakeResult, String> {
    let start = std::time::Instant::now();
    let mut rng = OsRng;

    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, ss_client) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "ML-KEM encapsulation failed".to_string())?;
    let ss_server = dk
        .decapsulate(&ct)
        .map_err(|_| "ML-KEM decapsulation failed".to_string())?;
    if ss_client != ss_server {
        return Err("ML-KEM shared secret mismatch".into());
    }

    let client_secret = StaticSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_secret);
    let server_secret = StaticSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);
    let dh_client = client_secret.diffie_hellman(&server_public);
    let dh_server = server_secret.diffie_hellman(&client_public);
    if dh_client.as_bytes() != dh_server.as_bytes() {
        return Err("X25519 shared secret mismatch".into());
    }

    let session_key = hybrid_kdf(ss_client.as_slice(), dh_client.as_bytes());
    let ct_bytes: &[u8] = ct.as_slice();
    let ek_encoded = ek.as_bytes();
    let secrets = SessionSecrets {
        session_key,
        fingerprint: fingerprint(&session_key),
        kem_ciphertext_preview: B64.encode(&ct_bytes[..36.min(ct_bytes.len())]),
        kem_ciphertext_bytes: ct_bytes.len(),
        kem_encaps_key_bytes: ek_encoded.len(),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    };
    Ok(to_handshake_result(&secrets))
}

// ---------- networked handshake (client side) ----------

#[derive(Deserialize, Clone, Debug)]
pub struct EdgeHello {
    pub handshake_id: String,
    pub kem_public_key_b64: String,
    pub server_x25519_pub_b64: String,
    pub server_wg_pub_b64: String,
    pub wg_endpoint: String,
}

#[derive(Serialize, Debug)]
pub struct ClientFinishRequest {
    pub handshake_id: String,
    pub kem_ciphertext_b64: String,
    pub client_x25519_pub_b64: String,
    pub client_wg_pub_b64: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct EdgeFinishResponse {
    pub ok: bool,
    pub session_fingerprint: String,
    pub client_vpn_ip: String,
    pub server_vpn_ip: String,
    pub dns: Option<String>,
}

/// Client completes a handshake against an edge Hello payload.
pub fn client_finish(
    hello: &EdgeHello,
    client_wg_pub_b64: &str,
) -> Result<(SessionSecrets, ClientFinishRequest), String> {
    let start = std::time::Instant::now();
    let mut rng = OsRng;

    let ek_bytes = B64
        .decode(&hello.kem_public_key_b64)
        .map_err(|e| format!("bad kem public key: {e}"))?;
    let ek = Ek::from_bytes(&encode_fixed(&ek_bytes)?);

    let (ct, ss_pq) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "ML-KEM encapsulation failed".to_string())?;

    let client_x = StaticSecret::random_from_rng(OsRng);
    let client_x_pub = PublicKey::from(&client_x);
    let server_x_bytes = B64
        .decode(&hello.server_x25519_pub_b64)
        .map_err(|e| format!("bad server x25519: {e}"))?;
    if server_x_bytes.len() != 32 {
        return Err("server X25519 public key must be 32 bytes".into());
    }
    let mut sx = [0u8; 32];
    sx.copy_from_slice(&server_x_bytes);
    let server_x_pub = PublicKey::from(sx);
    let ss_x = client_x.diffie_hellman(&server_x_pub);

    let session_key = hybrid_kdf(ss_pq.as_slice(), ss_x.as_bytes());
    let ct_bytes: &[u8] = ct.as_slice();
    let secrets = SessionSecrets {
        session_key,
        fingerprint: fingerprint(&session_key),
        kem_ciphertext_preview: B64.encode(&ct_bytes[..36.min(ct_bytes.len())]),
        kem_ciphertext_bytes: ct_bytes.len(),
        kem_encaps_key_bytes: ek_bytes.len(),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    };

    let req = ClientFinishRequest {
        handshake_id: hello.handshake_id.clone(),
        kem_ciphertext_b64: B64.encode(ct_bytes),
        client_x25519_pub_b64: B64.encode(client_x_pub.as_bytes()),
        client_wg_pub_b64: client_wg_pub_b64.to_string(),
    };
    Ok((secrets, req))
}

// ---------- networked handshake (server / edge side) ----------

pub struct ServerSession {
    pub handshake_id: String,
    dk: Dk,
    ek_b64: String,
    x_secret: StaticSecret,
    x_pub_b64: String,
    pub wg_pub_b64: String,
    pub wg_endpoint: String,
}

pub fn server_start(handshake_id: String, wg_pub_b64: String, wg_endpoint: String) -> ServerSession {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x_pub = PublicKey::from(&x_secret);
    ServerSession {
        handshake_id,
        dk,
        ek_b64: B64.encode(ek.as_bytes().as_slice()),
        x_secret,
        x_pub_b64: B64.encode(x_pub.as_bytes()),
        wg_pub_b64,
        wg_endpoint,
    }
}

impl ServerSession {
    pub fn hello(&self) -> EdgeHello {
        EdgeHello {
            handshake_id: self.handshake_id.clone(),
            kem_public_key_b64: self.ek_b64.clone(),
            server_x25519_pub_b64: self.x_pub_b64.clone(),
            server_wg_pub_b64: self.wg_pub_b64.clone(),
            wg_endpoint: self.wg_endpoint.clone(),
        }
    }

    pub fn finish(&self, req: &ClientFinishRequest) -> Result<SessionSecrets, String> {
        let start = std::time::Instant::now();
        let ct_bytes = B64
            .decode(&req.kem_ciphertext_b64)
            .map_err(|e| format!("bad ciphertext: {e}"))?;
        let ct = encode_ct(&ct_bytes)?;
        let ss_pq = self
            .dk
            .decapsulate(&ct)
            .map_err(|_| "ML-KEM decapsulation failed".to_string())?;

        let client_x_bytes = B64
            .decode(&req.client_x25519_pub_b64)
            .map_err(|e| format!("bad client x25519: {e}"))?;
        if client_x_bytes.len() != 32 {
            return Err("client X25519 public key must be 32 bytes".into());
        }
        let mut cx = [0u8; 32];
        cx.copy_from_slice(&client_x_bytes);
        let client_x_pub = PublicKey::from(cx);
        let ss_x = self.x_secret.diffie_hellman(&client_x_pub);

        let session_key = hybrid_kdf(ss_pq.as_slice(), ss_x.as_bytes());
        Ok(SessionSecrets {
            session_key,
            fingerprint: fingerprint(&session_key),
            kem_ciphertext_preview: B64.encode(&ct_bytes[..36.min(ct_bytes.len())]),
            kem_ciphertext_bytes: ct_bytes.len(),
            kem_encaps_key_bytes: B64.decode(&self.ek_b64).map(|b| b.len()).unwrap_or(1184),
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        })
    }
}
