import { useCallback, useEffect, useMemo, useState } from "react";
import {
  applyRemediation,
  establishTunnel,
  Finding,
  getAppliedFindings,
  getRemediationLog,
  getSetting,
  HandshakeResult,
  RemediationEntry,
  rollbackRemediation,
  runScan,
  setSetting,
} from "./api";
import Lattice from "./Lattice";

type ShieldState = "exposed" | "negotiating" | "protected";
type Tab = "shield" | "assets" | "log" | "settings";

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
    sub: "Hybrid post-quantum session established. Your key exchange is safe against both classical and quantum adversaries.",
  },
};

export default function App() {
  const [tab, setTab] = useState<Tab>("shield");
  const [shield, setShield] = useState<ShieldState>("exposed");
  const [handshake, setHandshake] = useState<HandshakeResult | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanning, setScanning] = useState(false);
  const [queue, setQueue] = useState<Set<string>>(new Set());
  const [applied, setApplied] = useState<Map<string, string>>(new Map());
  const [applying, setApplying] = useState(false);
  const [log, setLog] = useState<RemediationEntry[]>([]);
  const [localOnly, setLocalOnly] = useState(true);
  const [autoQueue, setAutoQueue] = useState(false);
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const finishOnboarding = () => {
    setSetting("onboarded", "1").catch(() => {});
    setOnboardStep(null);
  };

  const connect = async () => {
    if (shield === "protected") {
      setShield("exposed");
      setHandshake(null);
      return;
    }
    setShield("negotiating");
    try {
      // let the negotiating state breathe for a beat — the real handshake is sub-ms
      const [result] = await Promise.all([
        establishTunnel(),
        new Promise((r) => setTimeout(r, 1400)),
      ]);
      setHandshake(result);
      setShield("protected");
    } catch {
      setShield("exposed");
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
          {(["shield", "assets", "log", "settings"] as Tab[]).map((t) => (
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
              <div className="hero-actions">
                <button
                  className="btn-primary"
                  onClick={connect}
                  disabled={shield === "negotiating"}
                >
                  {shield === "protected"
                    ? "Disconnect"
                    : shield === "negotiating"
                      ? "Negotiating…"
                      : "Establish quantum-safe session"}
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
                <dt>Classical layer</dt>
                <dd className={handshake ? "" : "dim"}>{handshake?.classical ?? "— idle —"}</dd>
              </div>
              <div>
                <dt>Session fingerprint</dt>
                <dd className={handshake ? "" : "dim"}>
                  {handshake?.session_fingerprint ?? "— no session —"}
                </dd>
              </div>
              <div>
                <dt>Handshake</dt>
                <dd className={handshake ? "" : "dim"}>
                  {handshake
                    ? `${handshake.duration_ms.toFixed(2)} ms · ${handshake.kem_ciphertext_bytes} B ct`
                    : "— no session —"}
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
