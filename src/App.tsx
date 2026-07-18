import { useCallback, useEffect, useMemo, useState } from "react";
import {
  applyRemediation,
  connectTunnel,
  disconnectTunnel,
  Finding,
  getAppliedFindings,
  getRemediationLog,
  getSetting,
  HandshakeResult,
  RemediationEntry,
  rollbackRemediation,
  runScan,
  setSetting,
  TunnelStatus,
} from "./api";
import Lattice from "./Lattice";
import Technical from "./Technical";

type ShieldState = "exposed" | "negotiating" | "protected";
type Tab = "shield" | "assets" | "technical" | "log" | "settings";

/** Concrete fix steps for findings the app cannot safely change itself. */
const GUIDANCE: [string, string][] = [
  ["disk:filevault", "System Settings → Privacy & Security → FileVault → Turn On. Save the recovery key somewhere safe (not on this disk)."],
  ["os:version", "System Settings → General → Software Update. macOS 14+ ships hybrid post-quantum TLS."],
  ["git:signing", "Switch to SSH signing: git config --global gpg.format ssh && git config --global user.signingkey ~/.ssh/cryptiq_ed25519.pub"],
  ["ssh:known_hosts", "Ask each server's admin to enable Ed25519 host keys (HostKey /etc/ssh/ssh_host_ed25519_key), then reconnect to refresh the entry."],
  ["gpg:", "Generate a modern key: gpg --quick-generate-key \"You <you@email>\" ed25519 sign — then publish it and revoke the old key once contacts have switched."],
  ["keychain:", "Open Keychain Access, sort certificates by key size, delete ones you don't recognize; for ones tied to an app, ask that vendor to reissue."],
];

const guidanceFor = (id: string) =>
  GUIDANCE.find(([prefix]) => id.startsWith(prefix))?.[1] ?? null;

const STATE_COPY: Record<ShieldState, { word: string; sub: string }> = {
  exposed: {
    word: "Exposed",
    sub: "Your traffic is using classical cryptography only. Anything recorded today can be decrypted by a future quantum computer — harvest now, decrypt later.",
  },
  negotiating: {
    word: "Negotiating",
    sub: "Running the hybrid handshake: ML-KEM-768 lattice encapsulation combined with X25519. Both must be broken to recover your session key.",
  },
  protected: {
    word: "Protected",
    sub: "Hybrid post-quantum session established with the CryptiQ edge. Your control-plane key exchange is ML-KEM-768 + X25519; WireGuard carries the data plane.",
  },
};

export default function App() {
  const [tab, setTab] = useState<Tab>("shield");
  const [shield, setShield] = useState<ShieldState>("exposed");
  const [handshake, setHandshake] = useState<HandshakeResult | null>(null);
  const [tunnel, setTunnel] = useState<TunnelStatus | null>(null);
  const [edgeUrl, setEdgeUrl] = useState("http://64.181.224.148:8787");
  const [tunnelError, setTunnelError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanning, setScanning] = useState(false);
  const [queue, setQueue] = useState<Set<string>>(new Set());
  const [applied, setApplied] = useState<Map<string, string>>(new Map());
  const [applying, setApplying] = useState(false);
  const [log, setLog] = useState<RemediationEntry[]>([]);
  const [localOnly, setLocalOnly] = useState(true);
  const [autoQueue, setAutoQueue] = useState(false);
  const [fullTunnel, setFullTunnel] = useState(false);
  const [onboardStep, setOnboardStep] = useState<number | null>(null);

  const scan = useCallback(async () => {
    setScanning(true);
    try {
      const result = await runScan();
      setFindings(result);
      if (autoQueue) {
        setQueue((q) => {
          const next = new Set(q);
          result
            .filter((f) => f.remediation === "auto" && f.severity !== "ok")
            .forEach((f) => next.add(f.id));
          return next;
        });
      }
    } finally {
      setScanning(false);
    }
  }, [autoQueue]);

  useEffect(() => {
    scan();
    getRemediationLog().then(setLog).catch(() => {});
    // Applied migrations persist in SQLite; restore their state on launch.
    getAppliedFindings()
      .then((ids) =>
        setApplied(new Map(ids.map((id) => [id, "Migration applied — see remediation log"])))
      )
      .catch(() => {});
    getSetting("onboarded")
      .then((v) => {
        if (v !== "1") setOnboardStep(0);
      })
      .catch(() => {});
    getSetting("edge_url")
      .then((v) => {
        if (v) setEdgeUrl(v);
      })
      .catch(() => {});
    getSetting("full_tunnel")
      .then((v) => setFullTunnel(v === "1"))
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const finishOnboarding = () => {
    setSetting("onboarded", "1").catch(() => {});
    setOnboardStep(null);
  };

  const connect = async () => {
    if (shield === "protected" || shield === "negotiating") {
      if (shield === "protected") {
        try {
          await disconnectTunnel();
        } catch {
          /* ignore */
        }
        setShield("exposed");
        setHandshake(null);
        setTunnel(null);
        setTunnelError(null);
      }
      return;
    }
    setShield("negotiating");
    setTunnelError(null);
    try {
      await setSetting("edge_url", edgeUrl);
      const status = await connectTunnel(edgeUrl, fullTunnel);
      setTunnel(status);
      setHandshake(status.handshake);
      // config_ready still counts as protected for the PQ session; transport may be pending
      setShield("protected");
    } catch (e) {
      setShield("exposed");
      setTunnelError(typeof e === "string" ? e : "Could not reach the CryptiQ edge");
    }
  };

  const toggleQueue = (id: string) =>
    setQueue((q) => {
      const next = new Set(q);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const rollback = async (id: string) => {
    try {
      await rollbackRemediation(id);
      setApplied((m) => {
        const next = new Map(m);
        next.delete(id);
        return next;
      });
      setLog(await getRemediationLog());
    } catch {
      /* no snapshot — nothing to roll back */
    }
  };

  const applyQueue = async () => {
    setApplying(true);
    try {
      for (const id of queue) {
        try {
          const msg = await applyRemediation(id);
          setApplied((m) => new Map(m).set(id, msg));
        } catch {
          /* leave in queue-visible failed state; manual items can't reach here */
        }
      }
      setQueue(new Set());
      setLog(await getRemediationLog());
    } finally {
      setApplying(false);
    }
  };

  const counts = useMemo(
    () => ({
      critical: findings.filter((f) => f.severity === "critical").length,
      warn: findings.filter((f) => f.severity === "warn").length,
      ok: findings.filter((f) => f.severity === "ok").length,
    }),
    [findings]
  );

  const ONBOARD_STEPS = [
    {
      title: "Your laptop, quantum-safe",
      body: "CryptiQ Personal inventories every cryptographic asset on this machine — SSH keys, GPG keys, disk encryption, Wi-Fi, certificates — and shows you exactly what a future quantum computer could break.",
    },
    {
      title: "Nothing leaves this device",
      body: "Your asset inventory, scan history, and remediation log live in a local database on this laptop. CryptiQ servers never see what's on your machine.",
    },
    {
      title: "You approve every change",
      body: "Fixable findings go into a queue. Nothing is migrated until you review and apply — and every applied migration keeps a snapshot so you can roll it back with one click.",
    },
  ];

  return (
    <div className="app" data-state={shield}>
      <Lattice state={shield} />

      {onboardStep !== null && (
        <div className="onboard">
          <div className="onboard-card">
            <div className="onboard-step">
              {onboardStep + 1} / {ONBOARD_STEPS.length}
            </div>
            <h2>{ONBOARD_STEPS[onboardStep].title}</h2>
            <p>{ONBOARD_STEPS[onboardStep].body}</p>
            <div className="onboard-actions">
              <button className="btn-ghost" onClick={finishOnboarding}>
                Skip
              </button>
              <button
                className="btn-primary"
                onClick={() =>
                  onboardStep + 1 < ONBOARD_STEPS.length
                    ? setOnboardStep(onboardStep + 1)
                    : finishOnboarding()
                }
              >
                {onboardStep + 1 < ONBOARD_STEPS.length ? "Next" : "Run first scan"}
              </button>
            </div>
          </div>
        </div>
      )}

      <header className="topbar">
        <span className="wordmark">
          Crypti<b>Q</b> Personal
        </span>
        <nav className="nav">
          {(["shield", "assets", "technical", "log", "settings"] as Tab[]).map((t) => (
            <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
              {t}
            </button>
          ))}
        </nav>
      </header>

      <main className="pane">
        {tab === "shield" && (
          <>
            <section className="hero">
              <div className="state-label">Quantum shield · {shield}</div>
              <h1 className="state-word">{STATE_COPY[shield].word}</h1>
              <p className="state-sub">{STATE_COPY[shield].sub}</p>
              {tunnelError && <p className="tunnel-error">{tunnelError}</p>}
              {tunnel?.message && shield === "protected" && (
                <p className="tunnel-msg">{tunnel.message}</p>
              )}
              <div className="hero-actions">
                <button
                  className="btn-primary"
                  onClick={connect}
                  disabled={shield === "negotiating"}
                >
                  {shield === "protected"
                    ? "Disconnect"
                    : shield === "negotiating"
                      ? "Negotiating with edge…"
                      : "Connect quantum-safe tunnel"}
                </button>
                <button className="btn-ghost" onClick={() => setTab("assets")}>
                  {counts.critical + counts.warn} assets need attention
                </button>
              </div>
            </section>
            <dl className="readout">
              <div>
                <dt>Key encapsulation</dt>
                <dd className={handshake ? "" : "dim"}>{handshake?.kem ?? "— idle —"}</dd>
              </div>
              <div>
                <dt>Transport</dt>
                <dd className={tunnel ? "" : "dim"}>
                  {tunnel
                    ? tunnel.transport === "wireguard"
                      ? `WireGuard · ${tunnel.client_vpn_ip ?? "—"} · ${
                          tunnel.routing === "full_tunnel" ? "all traffic" : "edge only"
                        }`
                      : `Config ready · ${tunnel.state}`
                    : "— idle —"}
                </dd>
              </div>
              <div>
                <dt>Session fingerprint</dt>
                <dd className={handshake ? "" : "dim"}>
                  {handshake?.session_fingerprint ?? "— no session —"}
                </dd>
              </div>
              <div>
                <dt>Edge</dt>
                <dd className={tunnel ? "" : "dim"}>
                  {tunnel?.endpoint ?? tunnel?.edge_url ?? "— no edge —"}
                </dd>
              </div>
            </dl>
          </>
        )}

        {tab === "assets" && (
          <div className="assets">
            <div className="assets-head">
              <h2>Asset inventory</h2>
              <span className="counts">
                <b>{counts.critical}</b> critical · {counts.warn} warn · {counts.ok} safe
              </span>
              <span style={{ flex: 1 }} />
              <button className="btn-ghost" onClick={scan} disabled={scanning}>
                {scanning ? "Scanning…" : "Rescan"}
              </button>
            </div>
            {findings.map((f) => {
              const appliedMsg = applied.get(f.id);
              return (
                <div className="row" key={f.id}>
                  <span className={`tick ${f.severity}`} />
                  <div>
                    <div className="name">{f.name}</div>
                    <div className="detail">{appliedMsg ?? f.detail}</div>
                    {f.remediation === "manual" && guidanceFor(f.id) && (
                      <div className="guidance">How to fix: {guidanceFor(f.id)}</div>
                    )}
                  </div>
                  <div className="crypto">
                    <span className={appliedMsg ? "applied-old" : `cur ${f.severity === "critical" ? "bad" : ""}`}>
                      {f.current_crypto}
                    </span>
                    <span className="arrow">→</span>
                    <span className="tgt">{f.target_crypto}</span>
                  </div>
                  {appliedMsg ? (
                    <span className="chip-pair">
                      <button className="chip done">Migrated</button>
                      <button className="chip rollback" onClick={() => rollback(f.id)}>
                        Roll back
                      </button>
                    </span>
                  ) : f.remediation === "auto" ? (
                    <button
                      className={`chip ${queue.has(f.id) ? "queued" : "queue"}`}
                      onClick={() => toggleQueue(f.id)}
                    >
                      {queue.has(f.id) ? "Queued ✓" : "+ Queue"}
                    </button>
                  ) : f.remediation === "manual" ? (
                    <button className="chip manual">Manual</button>
                  ) : (
                    <span />
                  )}
                </div>
              );
            })}
            {queue.size > 0 && (
              <div className="queuebar">
                <span className="qcount">
                  <b>{queue.size}</b> migration{queue.size > 1 ? "s" : ""} staged
                </span>
                <span className="spacer" />
                <button className="btn-ghost" onClick={() => setQueue(new Set())}>
                  Clear
                </button>
                <button className="btn-primary" onClick={applyQueue} disabled={applying}>
                  {applying ? "Applying…" : "Review & apply"}
                </button>
              </div>
            )}
          </div>
        )}

        {tab === "technical" && (
          <Technical appliedIds={[...applied.keys()]} handshake={handshake} />
        )}

        {tab === "log" && (
          <div className="assets">
            <div className="assets-head">
              <h2>Remediation log</h2>
              <span className="counts">{log.length} entries · stored on-device</span>
            </div>
            {log.length === 0 && <div className="empty">No migrations applied yet.</div>}
            {log.map((e) => (
              <div className="log-entry" key={e.id}>
                <span className="when">{e.applied_at}</span>
                <span className="what">
                  {e.action} · {e.finding_id}
                </span>
                <span className="msg">{e.detail}</span>
              </div>
            ))}
          </div>
        )}

        {tab === "settings" && (
          <div className="assets">
            <div className="assets-head">
              <h2>Settings</h2>
            </div>
            <div className="setting">
              <div>
                <div className="s-name">Edge URL</div>
                <div className="s-desc">
                  CryptiQ edge that speaks the hybrid handshake. Default is the public CryptiQ
                  edge; for local development run{" "}
                  <span className="mono-inline">cargo run --manifest-path edge/Cargo.toml</span>{" "}
                  and set this to <span className="mono-inline">http://127.0.0.1:8787</span>
                </div>
              </div>
              <span className="spacer" />
              <input
                className="edge-input"
                value={edgeUrl}
                onChange={(e) => setEdgeUrl(e.target.value)}
                onBlur={() => setSetting("edge_url", edgeUrl).catch(() => {})}
                spellCheck={false}
              />
            </div>
            <div className="setting">
              <div>
                <div className="s-name">Route all traffic through the tunnel</div>
                <div className="s-desc">
                  Full-tunnel mode sets AllowedIPs to 0.0.0.0/0 and ::/0 and pins DNS to the edge,
                  so every packet leaves through the quantum-safe session — like a classic VPN.
                  Off means only traffic to the edge itself is tunneled. Takes effect on the next
                  connect.
                </div>
              </div>
              <span className="spacer" />
              <button
                className={`toggle ${fullTunnel ? "on" : ""}`}
                onClick={() => {
                  const next = !fullTunnel;
                  setFullTunnel(next);
                  setSetting("full_tunnel", next ? "1" : "0").catch(() => {});
                }}
                aria-label="Route all traffic through the tunnel"
              />
            </div>
            <div className="setting">
              <div>
                <div className="s-name">Keep inventory on-device</div>
                <div className="s-desc">
                  Your asset inventory, scan history, and remediation log live in a local SQLite
                  database and never touch CryptiQ servers. Turning this off is not yet available —
                  cloud sync ships with accounts.
                </div>
              </div>
              <span className="spacer" />
              <button
                className={`toggle ${localOnly ? "on" : ""}`}
                onClick={() => setLocalOnly(true)}
                aria-label="Keep inventory on-device"
              />
            </div>
            <div className="setting">
              <div>
                <div className="s-name">Auto-queue fixable findings</div>
                <div className="s-desc">
                  Every scan automatically stages safe migrations in the remediation queue. Nothing
                  is ever applied without your approval.
                </div>
              </div>
              <span className="spacer" />
              <button
                className={`toggle ${autoQueue ? "on" : ""}`}
                onClick={() => setAutoQueue((v) => !v)}
                aria-label="Auto-queue fixable findings"
              />
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
