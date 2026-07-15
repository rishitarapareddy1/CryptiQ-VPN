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
  duration_ms: number;
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
export const applyRemediation = (findingId: string) =>
  invoke<string>("apply_remediation", { findingId });
export const rollbackRemediation = (findingId: string) =>
  invoke<string>("rollback_remediation", { findingId });
export const getAppliedFindings = () => invoke<string[]>("get_applied_findings");
export const getRemediationLog = () => invoke<RemediationEntry[]>("get_remediation_log");
export const getSetting = (key: string) => invoke<string | null>("get_setting", { key });
export const setSetting = (key: string, value: string) =>
  invoke<void>("set_setting", { key, value });
