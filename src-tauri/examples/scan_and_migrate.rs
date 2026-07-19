//! One-off CLI harness: run the real scanner against this machine, print
//! findings, and (with --apply) run the real auto-migrations through the
//! same store the GUI app uses.
use cryptiq_personal_lib::{migrate, scanner, store};

fn main() {
    let apply = std::env::args().any(|a| a == "--apply");
    let db = store::open();

    let findings = scanner::run_full_scan();
    db.record_scan(&findings);

    println!("=== scan results ({}) ===", findings.len());
    for f in &findings {
        println!(
            "[{:<8}] {:<28} {:<8} {} -> {} ({})",
            f.severity, f.id, f.remediation, f.current_crypto, f.target_crypto, f.detail
        );
    }

    if !apply {
        println!("\n(dry run — pass --apply to actually run auto remediations)");
        return;
    }

    println!("\n=== applying auto remediations ===");
    for f in &findings {
        if f.remediation != "auto" {
            continue;
        }
        let result = if f.id.starts_with("ssh:") {
            migrate::apply_ssh_migration(&db, &f.id)
        } else if f.id == "net:wifi" {
            migrate::apply_wifi_policy(&db, &f.id)
        } else if f.id == "git:signing" {
            migrate::apply_git_signing(&db, &f.id)
        } else {
            continue;
        };
        match result {
            Ok(msg) => println!("OK  {}: {}", f.id, msg),
            Err(e) => println!("ERR {}: {}", f.id, e),
        }
    }
}
