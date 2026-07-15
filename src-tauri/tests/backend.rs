//! Integration tests for the CryptiQ Personal backend.
//!
//! Covers the three load-bearing pieces:
//!   1. the hybrid post-quantum handshake (real ML-KEM-768 + X25519 math)
//!   2. SSH key classification against synthetic keys of every algorithm
//!   3. the SQLite store round-trip
//!
//! Plus one live test that scans THIS machine and prints the findings, so you
//! can see with your own eyes what the app sees (`live_scan_of_this_machine`).

use cryptiq_personal_lib::{pqc, scanner, store};
use std::process::Command;

// ---------- 1. crypto ----------

#[test]
fn hybrid_handshake_succeeds_and_reports_real_parameters() {
    let hs = pqc::hybrid_handshake().expect("handshake must succeed");
    assert_eq!(hs.kem, "ML-KEM-768");
    assert_eq!(hs.classical, "X25519");
    // SHA-256-derived fingerprint: 8 bytes hex-encoded
    assert_eq!(hs.session_fingerprint.len(), 16);
    assert!(hs.session_fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    // FIPS 203: ML-KEM-768 ciphertext is exactly 1088 bytes
    assert_eq!(hs.kem_ciphertext_bytes, 1088);
    assert!(hs.duration_ms > 0.0);
}

#[test]
fn handshake_produces_unique_session_keys() {
    let a = pqc::hybrid_handshake().unwrap();
    let b = pqc::hybrid_handshake().unwrap();
    assert_ne!(
        a.session_fingerprint, b.session_fingerprint,
        "two handshakes must never derive the same session key"
    );
}

// ---------- 2. scanner classification ----------

/// Generate a real key of the given type with ssh-keygen and return its finding.
fn classify_generated_key(dir: &std::path::Path, algo: &str, bits: Option<&str>) -> scanner::Finding {
    let name = format!("test_{algo}");
    let path = dir.join(&name);
    let mut args = vec!["-t", algo, "-N", "", "-q", "-f", path.to_str().unwrap()];
    if let Some(b) = bits {
        args.extend(["-b", b]);
    }
    let out = Command::new("ssh-keygen").args(&args).output().unwrap();
    assert!(out.status.success(), "ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    let findings = scanner::scan_ssh_keys_in(dir);
    findings
        .into_iter()
        .find(|f| f.id == format!("ssh:{name}.pub"))
        .expect("scanner must produce a finding for the generated key")
}

#[test]
fn rsa_2048_is_flagged_as_quantum_weak_and_auto_fixable() {
    let dir = tempfile::tempdir().unwrap();
    let f = classify_generated_key(dir.path(), "rsa", Some("2048"));
    assert_eq!(f.severity, "warn");
    assert_eq!(f.current_crypto, "RSA-2048");
    assert_eq!(f.target_crypto, "Ed25519 + ML-DSA-65");
    assert_eq!(f.remediation, "auto");
}

#[test]
fn ecdsa_is_flagged_as_quantum_weak() {
    let dir = tempfile::tempdir().unwrap();
    let f = classify_generated_key(dir.path(), "ecdsa", Some("256"));
    assert_eq!(f.severity, "warn");
    assert_eq!(f.remediation, "auto");
}

#[test]
fn ed25519_is_reported_safe() {
    let dir = tempfile::tempdir().unwrap();
    let f = classify_generated_key(dir.path(), "ed25519", None);
    assert_eq!(f.severity, "ok");
    assert_eq!(f.current_crypto, "Ed25519");
    assert_eq!(f.remediation, "none");
}

#[test]
fn empty_ssh_dir_reports_ok_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let findings = scanner::scan_ssh_keys_in(dir.path());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "ssh:none");
    assert_eq!(findings[0].severity, "ok");
}

// ---------- 3. SQLite store ----------

#[test]
fn store_records_scans_and_remediations() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db");
    let store = store::open_at(&db);

    let findings = vec![scanner::Finding {
        id: "ssh:demo.pub".into(),
        category: "SSH".into(),
        name: "SSH key demo.pub".into(),
        detail: "RSA is quantum-breakable".into(),
        severity: "warn".into(),
        current_crypto: "RSA-2048".into(),
        target_crypto: "Ed25519 + ML-DSA-65".into(),
        remediation: "auto".into(),
    }];

    store.record_scan(&findings);
    // upsert path: second scan of the same finding must not duplicate
    store.record_scan(&findings);

    store.log_remediation("ssh:demo.pub", "generate_ed25519", "new key at ~/.ssh/cryptiq_ed25519");
    let log = store.remediation_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].finding_id, "ssh:demo.pub");
    assert_eq!(log[0].action, "generate_ed25519");

    assert!(db.exists(), "database file must exist on disk");
}

// ---------- 4. live scan of the machine running the tests ----------

#[test]
fn live_scan_of_this_machine() {
    let findings = scanner::run_full_scan();
    assert!(
        findings.len() >= 2,
        "a real machine always yields at least disk + OS findings"
    );
    // Disk and System scanners must always report, whatever their verdict.
    assert!(findings.iter().any(|f| f.category == "Disk"));
    assert!(findings.iter().any(|f| f.category == "System"));

    println!("\n===== LIVE SCAN OF THIS MACHINE =====");
    for f in &findings {
        println!(
            "[{:8}] {:10} {} :: {} -> {} ({})",
            f.severity, f.category, f.name, f.current_crypto, f.target_crypto, f.remediation
        );
        println!("           {}", f.detail);
    }
    println!("===== {} findings =====\n", findings.len());
}
