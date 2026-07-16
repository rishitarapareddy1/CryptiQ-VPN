import { invoke } from "@tauri-apps/api/core";

export interface Finding {
  id: string;
  category: string;
  name: string;
  detail: string;
  severity: "critical" | "warn" | "ok";
  current_crypto: string;
  target_crypto: string;
  remediation: "auto" | "manual" | "none";
}

export interface HandshakeResult {
  kem: string;
  classical: string;
  kdf: string;
  session_fingerprint: string;
  kem_ciphertext_preview: string;
  kem_ciphertext_bytes: number;
  kem_encaps_key_bytes: number;
  kem_shared_secret_bytes: number;
  classical_shared_secret_bytes: number;
  kdf_label: string;
  duration_ms: number;
}

export interface TunnelStatus {
  state: "down" | "handshaking" | "up" | "config_ready";
  handshake: HandshakeResult | null;
  edge_url: string;
  config_path: string | null;
  client_vpn_ip: string | null;
  endpoint: string | null;
  message: string;
  transport: "wireguard" | "handshake_only";
}

export interface MigrationDetail {
  finding_id: string;
  action: string;
  applied_at: string;
  summary: string;
  file_path: string | null;
  before: string | null;
  after: string | null;
  new_key_path: string | null;
  new_key_fingerprint: string | null;
}

export interface RemediationEntry {
  id: number;
  finding_id: string;
  action: string;
  detail: string;
  applied_at: string;
}

export const runScan = () => invoke<Finding[]>("run_scan");
export const establishTunnel = () => invoke<HandshakeResult>("establish_tunnel");
export const connectTunnel = (edgeUrl?: string) =>
  invoke<TunnelStatus>("connect_tunnel", { edgeUrl: edgeUrl ?? null });
export const disconnectTunnel = () => invoke<TunnelStatus>("disconnect_tunnel");
export const tunnelStatus = () => invoke<TunnelStatus>("tunnel_status");
export const applyRemediation = (findingId: string) =>
  invoke<string>("apply_remediation", { findingId });
export const rollbackRemediation = (findingId: string) =>
  invoke<string>("rollback_remediation", { findingId });
export const getAppliedFindings = () => invoke<string[]>("get_applied_findings");
export const getMigrationDetail = (findingId: string) =>
  invoke<MigrationDetail>("get_migration_detail", { findingId });
export const getRemediationLog = () => invoke<RemediationEntry[]>("get_remediation_log");
export const getSetting = (key: string) => invoke<string | null>("get_setting", { key });
export const setSetting = (key: string, value: string) =>
  invoke<void>("set_setting", { key, value });
