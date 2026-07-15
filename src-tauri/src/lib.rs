pub mod migrate;
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
        migrate::apply_ssh_migration(&store, &finding_id)
    } else if finding_id == "net:wifi" {
        migrate::apply_wifi_policy(&store, &finding_id)
    } else {
        Err("This finding requires manual remediation".into())
    }
}

#[tauri::command]
fn rollback_remediation(store: State<Store>, finding_id: String) -> Result<String, String> {
    migrate::rollback(&store, &finding_id)
}

#[tauri::command]
fn get_applied_findings(store: State<Store>) -> Vec<String> {
    store.applied_findings()
}

#[tauri::command]
fn get_migration_detail(
    store: State<Store>,
    finding_id: String,
) -> Result<migrate::MigrationDetail, String> {
    migrate::migration_detail(&store, &finding_id)
}

#[tauri::command]
fn get_remediation_log(store: State<Store>) -> Vec<RemediationEntry> {
    store.remediation_log()
}

#[tauri::command]
fn get_setting(store: State<Store>, key: String) -> Option<String> {
    store.get_setting(&key)
}

#[tauri::command]
fn set_setting(store: State<Store>, key: String, value: String) {
    store.set_setting(&key, &value);
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;
    use tauri::Manager;

    let open = MenuItem::with_id(app, "open", "Open CryptiQ Personal", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;

    TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .icon_as_template(true)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(win) = app.get_webview_window("main") {
                    win.show().ok();
                    win.set_focus().ok();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(store::open())
        .setup(|app| {
            setup_tray(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            run_scan,
            establish_tunnel,
            apply_remediation,
            rollback_remediation,
            get_applied_findings,
            get_migration_detail,
            get_remediation_log,
            get_setting,
            set_setting
        ])
        .run(tauri::generate_context!())
        .expect("error while running CryptiQ Personal");
}
