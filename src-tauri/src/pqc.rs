//! Hybrid post-quantum handshake: ML-KEM-768 (FIPS 203) + X25519.
//!
//! The key exchange math here is real — actual lattice KEM encapsulation and
//! actual ECDH, combined through a SHA-256 KDF the way hybrid TLS drafts do it.
//! In v1 both sides of the exchange run in-process; wiring the resulting keys
//! into a WireGuard tunnel to a CryptiQ edge node is the v2 transport work.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Serialize, Clone)]
pub struct HandshakeResult {
    pub kem: String,
    pub classical: String,
    pub kdf: String,
    pub session_fingerprint: String,
    pub kem_ciphertext_preview: String,
    pub kem_ciphertext_bytes: usize,
    pub duration_ms: f64,
}

pub fn hybrid_handshake() -> Result<HandshakeResult, String> {
    let start = std::time::Instant::now();
    let mut rng = OsRng;

    // Post-quantum side: fresh ML-KEM-768 keypair, encapsulate, decapsulate,
    // and verify both ends derived the same shared secret.
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

    // Classical side: ephemeral X25519 ECDH.
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_secret);
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);
    let dh_client = client_secret.diffie_hellman(&server_public);
    let dh_server = server_secret.diffie_hellman(&client_public);
    if dh_client.as_bytes() != dh_server.as_bytes() {
        return Err("X25519 shared secret mismatch".into());
    }

    // Hybrid KDF: an attacker must break BOTH the lattice KEM and the curve
    // to recover the session key.
    let mut kdf = Sha256::new();
    kdf.update(b"cryptiq-personal-hybrid-v1");
    kdf.update(ss_client.as_slice());
    kdf.update(dh_client.as_bytes());
    let session_key = kdf.finalize();

    let ct_bytes: &[u8] = ct.as_slice();
    Ok(HandshakeResult {
        kem: "ML-KEM-768".into(),
        classical: "X25519".into(),
        kdf: "SHA-256 hybrid".into(),
        session_fingerprint: session_key[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(""),
        kem_ciphertext_preview: B64.encode(&ct_bytes[..36]),
        kem_ciphertext_bytes: ct_bytes.len(),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    })
}
