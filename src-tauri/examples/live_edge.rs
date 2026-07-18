fn main() {
    let full_tunnel = std::env::args().any(|a| a == "--full-tunnel");
    let tm = cryptiq_personal_lib::tunnel::TunnelManager::new();
    match tm.connect(Some("http://127.0.0.1:8787".into()), full_tunnel) {
        Ok(s) => {
            println!("OK state={} transport={} routing={}", s.state, s.transport, s.routing);
            println!(
                "fingerprint={}",
                s.handshake
                    .as_ref()
                    .map(|h| h.session_fingerprint.clone())
                    .unwrap_or_default()
            );
            println!("vpn={}", s.client_vpn_ip.unwrap_or_default());
            println!("config={}", s.config_path.unwrap_or_default());
            println!("{}", s.message);
            let _ = tm.disconnect();
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}
