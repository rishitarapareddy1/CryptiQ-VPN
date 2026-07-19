pub mod migrate;
pub mod pqc;
pub mod scanner;
pub mod store;
pub mod tunnel;

use scanner::Finding;
use store::{RemediationEntry, Store};
use tauri::State;
use tunnel::{TunnelManager, TunnelStatus};

#[tauri::command]
fn run_scan(store: State<Store>) -> Vec<Finding> {
    let findings = scanner::run_full_scan();
    store.record_scan(&findings);
    findings
}

/// Back-compat: offline in-process handshake (no edge, no WireGuard).
#[tauri::command]
fn establish_tunnel() -> Result<pqc::HandshakeResult, String> {
    pqc::hybrid_handshake()
}

#[tauri::command]
fn connect_tunnel(
    tunnels: State<TunnelManager>,
    store: State<Store>,
    edge_url: Option<String>,
    full_tunnel: Option<bool>,
) -> Result<TunnelStatus, String> {
    let url = edge_url.or_else(|| store.get_setting("edge_url"));
    let mut full = full_tunnel.unwrap_or_else(|| {
        store
            .get_setting("full_tunnel")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
    });
    // Wi-Fi policy: untrusted networks force full-tunnel routing.
    if store
        .get_setting("force_tunnel_untrusted")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        full = true;
    }
    tunnels.connect(url, full)
}

#[tauri::command]
fn disconnect_tunnel(tunnels: State<TunnelManager>) -> Result<TunnelStatus, String> {
    tunnels.disconnect()
}

#[tauri::command]
fn tunnel_status(tunnels: State<TunnelManager>) -> TunnelStatus {
    tunnels.status()
}

#[tauri::command]
fn apply_remediation(store: State<Store>, finding_id: String) -> Result<String, String> {
    if finding_id.starts_with("ssh:")
        && finding_id != "ssh:known_hosts"
        && finding_id != "ssh:none"
    {
        migrate::apply_ssh_migration(&store, &finding_id)
    } else if finding_id == "net:wifi" {
        migrate::apply_wifi_policy(&store, &finding_id)
    } else if finding_id == "git:signing" {
        migrate::apply_git_signing(&store, &finding_id)
    } else {
        Err("This finding requires manual remediation".into())
    }
}

/// Retry bringing up an already-written WireGuard config (admin dialog).
#[tauri::command]
fn bring_up_tunnel(tunnels: State<TunnelManager>) -> Result<TunnelStatus, String> {
    tunnels.bring_up()
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
        .manage(tunnel::TunnelManager::new())
        .setup(|app| {
            setup_tray(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            run_scan,
            establish_tunnel,
            connect_tunnel,
            disconnect_tunnel,
            bring_up_tunnel,
            tunnel_status,
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
