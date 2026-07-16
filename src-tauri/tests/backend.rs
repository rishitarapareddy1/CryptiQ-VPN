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

// ---------- 4. snapshots, applied-state, and rollback bookkeeping ----------

#[test]
fn snapshot_round_trip_preserves_exact_content() {
    let dir = tempfile::tempdir().unwrap();
    let store = store::open_at(&dir.path().join("t.db"));

    store.save_snapshot("ssh:demo.pub", "/tmp/fake_config", Some("Host old\n  User me\n"));
    let snap = store.latest_snapshot("ssh:demo.pub").expect("snapshot must exist");
    assert_eq!(snap.file_path, "/tmp/fake_config");
    assert_eq!(snap.content.as_deref(), Some("Host old\n  User me\n".as_bytes()));

    // None content = file did not exist before migration
    store.save_snapshot("ssh:other.pub", "/tmp/never_existed", None);
    let snap2 = store.latest_snapshot("ssh:other.pub").unwrap();
    assert!(snap2.content.is_none());
}

#[test]
fn applied_findings_tracks_latest_action_and_rollback_clears_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = store::open_at(&dir.path().join("t.db"));

    store.log_remediation("ssh:a.pub", "ssh_migration", "migrated");
    store.log_remediation("net:wifi", "wifi_policy", "policy on");
    let mut applied = store.applied_findings();
    applied.sort();
    assert_eq!(applied, vec!["net:wifi", "ssh:a.pub"]);

    // Rolling back removes it from the applied set — latest action wins.
    store.log_remediation("ssh:a.pub", "rollback", "restored");
    assert_eq!(store.applied_findings(), vec!["net:wifi"]);
}

#[test]
fn wifi_policy_applies_and_rolls_back_via_settings() {
    let dir = tempfile::tempdir().unwrap();
    let store = store::open_at(&dir.path().join("t.db"));

    cryptiq_personal_lib::migrate::apply_wifi_policy(&store, "net:wifi").unwrap();
    assert_eq!(store.get_setting("force_tunnel_untrusted").as_deref(), Some("1"));
    assert_eq!(store.applied_findings(), vec!["net:wifi"]);

    cryptiq_personal_lib::migrate::rollback(&store, "net:wifi").unwrap();
    assert_eq!(store.get_setting("force_tunnel_untrusted").as_deref(), Some("0"));
    assert!(store.applied_findings().is_empty());
}

#[test]
fn settings_upsert() {
    let dir = tempfile::tempdir().unwrap();
    let store = store::open_at(&dir.path().join("t.db"));
    assert!(store.get_setting("onboarded").is_none());
    store.set_setting("onboarded", "1");
    store.set_setting("onboarded", "0");
    assert_eq!(store.get_setting("onboarded").as_deref(), Some("0"));
}

// ---------- 5. technical audit: migration detail ----------

#[test]
fn migration_detail_returns_before_and_after_content() {
    let dir = tempfile::tempdir().unwrap();
    let store = store::open_at(&dir.path().join("t.db"));

    let file = dir.path().join("ssh_config");
    std::fs::write(&file, "Host old\n\n# managed block\nIdentityFile new\n").unwrap();
    store.save_snapshot("ssh:x.pub", &file.to_string_lossy(), Some("Host old\n"));
    store.log_remediation("ssh:x.pub", "config_edit", "added managed block");

    let d = cryptiq_personal_lib::migrate::migration_detail(&store, "ssh:x.pub").unwrap();
    assert_eq!(d.finding_id, "ssh:x.pub");
    assert_eq!(d.action, "config_edit");
    assert_eq!(d.before.as_deref(), Some("Host old\n"));
    assert_eq!(
        d.after.as_deref(),
        Some("Host old\n\n# managed block\nIdentityFile new\n")
    );
    assert_eq!(d.file_path.as_deref(), Some(&*file.to_string_lossy()));
}

#[test]
fn migration_detail_errors_when_nothing_was_applied() {
    let dir = tempfile::tempdir().unwrap();
    let store = store::open_at(&dir.path().join("t.db"));
    assert!(cryptiq_personal_lib::migrate::migration_detail(&store, "ssh:ghost.pub").is_err());
}

#[test]
fn handshake_exposes_full_fips203_parameters() {
    let hs = cryptiq_personal_lib::pqc::hybrid_handshake().unwrap();
    // FIPS 203 ML-KEM-768: encapsulation key 1184 B, ciphertext 1088 B, shared secret 32 B
    assert_eq!(hs.kem_encaps_key_bytes, 1184);
    assert_eq!(hs.kem_ciphertext_bytes, 1088);
    assert_eq!(hs.kem_shared_secret_bytes, 32);
    assert_eq!(hs.classical_shared_secret_bytes, 32);
    assert_eq!(hs.kdf_label, "cryptiq-personal-hybrid-v1");
}

#[test]
fn networked_handshake_client_and_server_agree() {
    let (hs, conf) = cryptiq_personal_lib::tunnel::simulate_peer_exchange().unwrap();
    assert_eq!(hs.kem, "ML-KEM-768");
    assert_eq!(hs.kem_ciphertext_bytes, 1088);
    assert!(conf.contains("[Interface]"));
    assert!(conf.contains("[Peer]"));
    assert!(conf.contains("PersistentKeepalive"));
}

#[test]
fn wg_conf_render_includes_dns_when_provided() {
    let conf = cryptiq_personal_lib::tunnel::render_wg_conf(
        "priv",
        "10.66.66.2",
        "pub",
        "127.0.0.1:51820",
        "10.66.66.1",
        Some("1.1.1.1"),
    );
    assert!(conf.contains("DNS = 1.1.1.1"));
    assert!(conf.contains("AllowedIPs = 10.66.66.1/32"));
}

// ---------- 6. live scan of the machine running the tests ----------

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
