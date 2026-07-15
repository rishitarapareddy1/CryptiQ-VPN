pub mod pqc;
pub mod scanner;
pub mod store;

use scanner::Finding;
use store::{RemediationEntry, Store};
use tauri::State;

#[tauri::command]
fn run_scan(store: State<Store>) -> Vec<Finding> {
    let findings = scanner::run_full_scan();
    store.record_scan(&findings);
    findings
}

#[tauri::command]
fn establish_tunnel() -> Result<pqc::HandshakeResult, String> {
    pqc::hybrid_handshake()
}

#[tauri::command]
fn apply_remediation(store: State<Store>, finding_id: String) -> Result<String, String> {
    if finding_id.starts_with("ssh:") {
        let msg = scanner::generate_replacement_key()?;
        store.log_remediation(&finding_id, "generate_ed25519", &msg);
        Ok(msg)
    } else {
        Err("This finding requires manual remediation".into())
    }
}

#[tauri::command]
fn get_remediation_log(store: State<Store>) -> Vec<RemediationEntry> {
    store.remediation_log()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(store::open())
        .invoke_handler(tauri::generate_handler![
            run_scan,
            establish_tunnel,
            apply_remediation,
            get_remediation_log
        ])
        .run(tauri::generate_context!())
        .expect("error while running CryptiQ Personal");
}
