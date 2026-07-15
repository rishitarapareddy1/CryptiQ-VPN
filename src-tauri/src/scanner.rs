//! Real macOS asset scanners. Everything here reads actual state from the
//! machine: SSH keys on disk, FileVault status, OS version, Git signing config.
//! Nothing leaves the device — results go straight into the local SQLite store.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub name: String,
    pub detail: String,
    /// "critical" | "warn" | "ok"
    pub severity: String,
    pub current_crypto: String,
    pub target_crypto: String,
    /// "auto" = app can fix it safely, "manual" = user/vendor action needed, "none" = already fine
    pub remediation: String,
}

pub fn run_full_scan() -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_ssh_keys());
    findings.push(scan_filevault());
    findings.push(scan_os_version());
    if let Some(f) = scan_git_signing() {
        findings.push(f);
    }
    if let Some(f) = scan_known_hosts() {
        findings.push(f);
    }
    findings.extend(scan_gpg_keys());
    if let Some(f) = scan_wifi() {
        findings.push(f);
    }
    if let Some(f) = scan_keychain_certs() {
        findings.push(f);
    }
    findings
}

/// Parse every public key in ~/.ssh and classify its algorithm.
fn scan_ssh_keys() -> Vec<Finding> {
    match dirs::home_dir() {
        Some(h) => scan_ssh_keys_in(&h.join(".ssh")),
        None => Vec::new(),
    }
}

/// Scan an arbitrary directory of SSH public keys (separated out for tests).
pub fn scan_ssh_keys_in(ssh_dir: &std::path::Path) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            if let Some(f) = classify_ssh_key(&path) {
                out.push(f);
            }
        }
    }

    if out.is_empty() {
        out.push(Finding {
            id: "ssh:none".into(),
            category: "SSH".into(),
            name: "No SSH keys found".into(),
            detail: format!("{} contains no public keys", ssh_dir.display()),
            severity: "ok".into(),
            current_crypto: "—".into(),
            target_crypto: "—".into(),
            remediation: "none".into(),
        });
    }
    out
}

fn classify_ssh_key(path: &PathBuf) -> Option<Finding> {
    let content = std::fs::read_to_string(path).ok()?;
    let algo = content.split_whitespace().next()?.to_string();
    let name = path.file_name()?.to_string_lossy().to_string();

    // Bit length via ssh-keygen fingerprint output ("2048 SHA256:... (RSA)").
    let bits = Command::new("ssh-keygen")
        .args(["-l", "-f"])
        .arg(path)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .and_then(|b| b.parse::<u32>().ok())
        });

    let (severity, current, target, remediation, detail) = match algo.as_str() {
        "ssh-rsa" => {
            let b = bits.unwrap_or(2048);
            let sev = if b < 2048 { "critical" } else { "warn" };
            (
                sev,
                format!("RSA-{b}"),
                "Ed25519 + ML-DSA-65".to_string(),
                "auto",
                format!("RSA is quantum-breakable via Shor's algorithm ({b}-bit key)"),
            )
        }
        "ssh-dss" => (
            "critical",
            "DSA-1024".to_string(),
            "Ed25519 + ML-DSA-65".to_string(),
            "auto",
            "DSA is deprecated by OpenSSH and quantum-breakable".to_string(),
        ),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => (
            "warn",
            "ECDSA (NIST curve)".to_string(),
            "Ed25519 + ML-DSA-65".to_string(),
            "auto",
            "ECDSA is quantum-breakable; migrate to a hybrid signature".to_string(),
        ),
        "ssh-ed25519" => (
            "ok",
            "Ed25519".to_string(),
            "Ed25519 + ML-DSA-65 (hybrid)".to_string(),
            "none",
            "Strong classical signature; pair with ML-DSA when servers support it".to_string(),
        ),
        _ => (
            "warn",
            algo.clone(),
            "Ed25519 + ML-DSA-65".to_string(),
            "manual",
            format!("Unrecognized key type {algo}"),
        ),
    };

    Some(Finding {
        id: format!("ssh:{name}"),
        category: "SSH".into(),
        name: format!("SSH key {name}"),
        detail,
        severity: severity.into(),
        current_crypto: current,
        target_crypto: target,
        remediation: remediation.into(),
    })
}

/// FileVault full-disk encryption status via fdesetup.
fn scan_filevault() -> Finding {
    let on = Command::new("fdesetup")
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("FileVault is On"))
        .unwrap_or(false);

    if on {
        Finding {
            id: "disk:filevault".into(),
            category: "Disk".into(),
            name: "FileVault disk encryption".into(),
            detail: "Full-disk encryption enabled (AES-XTS is quantum-resistant at 256-bit)".into(),
            severity: "ok".into(),
            current_crypto: "AES-XTS-128/256".into(),
            target_crypto: "AES-XTS-256".into(),
            remediation: "none".into(),
        }
    } else {
        Finding {
            id: "disk:filevault".into(),
            category: "Disk".into(),
            name: "FileVault disk encryption".into(),
            detail: "Disk is not encrypted — anyone with physical access can read your data".into(),
            severity: "critical".into(),
            current_crypto: "None".into(),
            target_crypto: "AES-XTS-256".into(),
            remediation: "manual".into(),
        }
    }
}

/// OS version — newer macOS ships hybrid PQ in iMessage/TLS stack.
fn scan_os_version() -> Finding {
    let ver = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let major: u32 = ver.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);

    if major >= 14 {
        Finding {
            id: "os:version".into(),
            category: "System".into(),
            name: format!("macOS {ver}"),
            detail: "OS TLS stack supports hybrid post-quantum key exchange".into(),
            severity: "ok".into(),
            current_crypto: "X25519 + Kyber (system TLS)".into(),
            target_crypto: "X25519MLKEM768".into(),
            remediation: "none".into(),
        }
    } else {
        Finding {
            id: "os:version".into(),
            category: "System".into(),
            name: format!("macOS {ver}"),
            detail: "Older OS — system TLS lacks post-quantum key exchange. Update macOS.".into(),
            severity: "warn".into(),
            current_crypto: "Classical TLS only".into(),
            target_crypto: "X25519MLKEM768".into(),
            remediation: "manual".into(),
        }
    }
}

/// Git commit signing key, if configured with RSA.
fn scan_git_signing() -> Option<Finding> {
    let out = Command::new("git")
        .args(["config", "--global", "gpg.format"])
        .output()
        .ok()?;
    let format = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if format.is_empty() {
        return None;
    }
    if format == "ssh" {
        Some(Finding {
            id: "git:signing".into(),
            category: "Git".into(),
            name: "Git commit signing".into(),
            detail: "Signing with SSH key — algorithm follows your SSH key posture".into(),
            severity: "ok".into(),
            current_crypto: "SSH signature".into(),
            target_crypto: "Ed25519 + ML-DSA-65".into(),
            remediation: "none".into(),
        })
    } else {
        Some(Finding {
            id: "git:signing".into(),
            category: "Git".into(),
            name: "Git commit signing (GPG)".into(),
            detail: "GPG keys are typically RSA — quantum-breakable signatures on your commits".into(),
            severity: "warn".into(),
            current_crypto: "GPG (likely RSA)".into(),
            target_crypto: "Ed25519 SSH signing".into(),
            remediation: "manual".into(),
        })
    }
}

/// Host keys in ~/.ssh/known_hosts still using ssh-rsa — an aggregate finding,
/// since the fix is on the server side of each connection.
fn scan_known_hosts() -> Option<Finding> {
    let path = dirs::home_dir()?.join(".ssh").join("known_hosts");
    let content = std::fs::read_to_string(&path).ok()?;
    let total = content.lines().filter(|l| !l.trim().is_empty()).count();
    if total == 0 {
        return None;
    }
    let weak = content
        .lines()
        .filter(|l| l.contains(" ssh-rsa ") || l.contains(" ssh-dss "))
        .count();

    Some(if weak > 0 {
        Finding {
            id: "ssh:known_hosts".into(),
            category: "SSH".into(),
            name: "Known hosts (server keys)".into(),
            detail: format!(
                "{weak} of {total} remembered servers present RSA/DSA host keys. \
                 The fix is server-side; reconnecting after servers upgrade refreshes these."
            ),
            severity: "warn".into(),
            current_crypto: format!("{weak}× ssh-rsa/dss"),
            target_crypto: "ssh-ed25519".into(),
            remediation: "manual".into(),
        }
    } else {
        Finding {
            id: "ssh:known_hosts".into(),
            category: "SSH".into(),
            name: "Known hosts (server keys)".into(),
            detail: format!("All {total} remembered server keys use modern algorithms"),
            severity: "ok".into(),
            current_crypto: "ssh-ed25519 / ecdsa".into(),
            target_crypto: "ssh-ed25519".into(),
            remediation: "none".into(),
        }
    })
}

/// GPG keyring, if gpg is installed. Colon format: pub line field 4 is the
/// algorithm id (1/2/3 = RSA, 16/17 = ElGamal/DSA, 18 = ECDH, 19 = ECDSA, 22 = EdDSA).
fn scan_gpg_keys() -> Vec<Finding> {
    let out = match Command::new("gpg")
        .args(["--list-keys", "--with-colons"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(), // gpg not installed or no keyring — not a finding
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut findings = Vec::new();
    for line in text.lines().filter(|l| l.starts_with("pub:")) {
        let fields: Vec<&str> = line.split(':').collect();
        let bits = fields.get(2).unwrap_or(&"?");
        let algo_id: u32 = fields.get(3).and_then(|a| a.parse().ok()).unwrap_or(0);
        let key_id = fields.get(4).map(|k| k.to_string()).unwrap_or_default();
        let short_id = key_id.chars().rev().take(8).collect::<String>().chars().rev().collect::<String>();

        let (severity, current) = match algo_id {
            1..=3 => ("warn", format!("RSA-{bits}")),
            16 | 17 => ("critical", format!("DSA/ElGamal-{bits}")),
            18 | 19 => ("warn", "ECC (NIST)".to_string()),
            22 => ("ok", "EdDSA (Ed25519)".to_string()),
            _ => ("warn", format!("algo #{algo_id}")),
        };
        findings.push(Finding {
            id: format!("gpg:{key_id}"),
            category: "GPG".into(),
            name: format!("GPG key …{short_id}"),
            detail: if severity == "ok" {
                "Modern curve signature; quantum-safe GPG requires a future ML-DSA-capable release".into()
            } else {
                "Quantum-breakable public key in your GPG keyring. Generate an Ed25519 GPG key and re-sign; revoke this one when peers have migrated.".into()
            },
            severity: severity.into(),
            current_crypto: current,
            target_crypto: "Ed25519 (GPG) → ML-DSA when supported".into(),
            remediation: "manual".into(),
        });
    }
    findings
}

/// Security mode of the Wi-Fi network the laptop is currently on.
fn scan_wifi() -> Option<Finding> {
    let out = Command::new("system_profiler")
        .args(["SPAirPortDataType", "-detailLevel", "basic"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);

    // The current network block appears under "Current Network Information:";
    // its "Security:" line is the first one after that marker.
    let after = text.split("Current Network Information:").nth(1)?;
    let security = after
        .lines()
        .find_map(|l| l.trim().strip_prefix("Security:").map(|s| s.trim().to_string()))?;

    let (severity, remediation, detail) = if security.contains("WPA3") {
        ("ok", "none", "WPA3 uses SAE — strong against offline capture".to_string())
    } else if security.contains("WPA2") {
        (
            "warn",
            "auto",
            "WPA2 traffic can be captured today and decrypted later. The CryptiQ tunnel wraps it in quantum-safe encryption.".to_string(),
        )
    } else if security.to_lowercase().contains("none") || security.contains("Open") {
        (
            "critical",
            "auto",
            "Open network — all traffic visible. Tunnel required.".to_string(),
        )
    } else {
        ("warn", "auto", format!("Legacy security mode: {security}"))
    };

    Some(Finding {
        id: "net:wifi".into(),
        category: "Network".into(),
        name: "Current Wi-Fi network".into(),
        detail,
        severity: severity.into(),
        current_crypto: security,
        target_crypto: "ML-KEM-768 tunnel".into(),
        remediation: remediation.into(),
    })
}

/// Aggregate look at certificates in the login Keychain: how many carry
/// weak (<2048-bit) RSA public keys.
fn scan_keychain_certs() -> Option<Finding> {
    let home = dirs::home_dir()?;
    let keychain = home.join("Library/Keychains/login.keychain-db");
    let out = Command::new("security")
        .args(["find-certificate", "-a", "-p"])
        .arg(&keychain)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let pem = String::from_utf8_lossy(&out.stdout);
    let certs: Vec<String> = pem
        .split("-----END CERTIFICATE-----")
        .filter(|c| c.contains("-----BEGIN CERTIFICATE-----"))
        .map(|c| format!("{c}-----END CERTIFICATE-----\n"))
        .collect();
    if certs.is_empty() {
        return None;
    }

    let mut weak = 0usize;
    for cert in &certs {
        // `openssl x509 -text` prints e.g. "Public-Key: (1024 bit)" with "rsaEncryption".
        use std::io::Write;
        use std::process::Stdio;
        let Ok(mut child) = Command::new("openssl")
            .args(["x509", "-noout", "-text"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return None; // no openssl — skip this scanner entirely
        };
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(cert.as_bytes()).ok();
        }
        if let Ok(o) = child.wait_with_output() {
            let txt = String::from_utf8_lossy(&o.stdout);
            let is_rsa = txt.contains("rsaEncryption");
            let bits = txt
                .lines()
                .find_map(|l| {
                    let l = l.trim();
                    l.strip_prefix("Public-Key: (")
                        .and_then(|r| r.split_whitespace().next())
                        .and_then(|b| b.parse::<u32>().ok())
                })
                .unwrap_or(0);
            if is_rsa && bits > 0 && bits < 2048 {
                weak += 1;
            }
        }
    }

    Some(if weak > 0 {
        Finding {
            id: "keychain:certs".into(),
            category: "Keychain".into(),
            name: "Login Keychain certificates".into(),
            detail: format!(
                "{weak} of {} certificates carry RSA keys under 2048 bits — breakable classically soon, quantum-trivial. These belong to the apps/services that issued them; remove or ask the vendor to reissue.",
                certs.len()
            ),
            severity: "warn".into(),
            current_crypto: format!("{weak}× RSA<2048"),
            target_crypto: "RSA-3072+ / ECDSA → ML-DSA".into(),
            remediation: "manual".into(),
        }
    } else {
        Finding {
            id: "keychain:certs".into(),
            category: "Keychain".into(),
            name: "Login Keychain certificates".into(),
            detail: format!("All {} certificates use ≥2048-bit keys", certs.len()),
            severity: "ok".into(),
            current_crypto: "RSA-2048+ / ECDSA".into(),
            target_crypto: "ML-DSA when CAs issue it".into(),
            remediation: "none".into(),
        }
    })
}

/// The one remediation v1 performs for real, and it is non-destructive:
/// generate a fresh Ed25519 keypair at ~/.ssh/cryptiq_ed25519 without touching
/// any existing key. The user swaps it in on their own servers/GitHub.
pub fn generate_replacement_key() -> Result<String, String> {
    let home = dirs::home_dir().ok_or("no home directory")?;
    let key_path = home.join(".ssh").join("cryptiq_ed25519");
    if key_path.exists() {
        return Ok(format!("{} already exists — reusing it", key_path.display()));
    }
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "cryptiq-personal-migration", "-f"])
        .arg(&key_path)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(format!("New Ed25519 keypair written to {}", key_path.display()))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}
