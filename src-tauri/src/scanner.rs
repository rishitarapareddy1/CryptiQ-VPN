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
