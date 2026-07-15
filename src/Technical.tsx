import { useEffect, useState } from "react";
import { getMigrationDetail, HandshakeResult, MigrationDetail } from "./api";

type DiffOp = { type: "same" | "add" | "del"; text: string };

/** Classic LCS line diff — files here are small (ssh configs), so O(n·m) is fine. */
function lineDiff(before: string, after: string): DiffOp[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const ops: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ type: "same", text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      ops.push({ type: "del", text: a[i++] });
    } else {
      ops.push({ type: "add", text: b[j++] });
    }
  }
  while (i < n) ops.push({ type: "del", text: a[i++] });
  while (j < m) ops.push({ type: "add", text: b[j++] });
  return ops;
}

export default function Technical({
  appliedIds,
  handshake,
}: {
  appliedIds: string[];
  handshake: HandshakeResult | null;
}) {
  const [details, setDetails] = useState<MigrationDetail[]>([]);

  useEffect(() => {
    Promise.all(appliedIds.map((id) => getMigrationDetail(id).catch(() => null))).then((all) =>
      setDetails(all.filter((d): d is MigrationDetail => d !== null))
    );
  }, [appliedIds]);

  return (
    <div className="assets">
      <div className="assets-head">
        <h2>Technical audit</h2>
        <span className="counts">exact record of every change this app has made</span>
      </div>

      <section className="tech-section">
        <h3>Session cryptography</h3>
        {handshake ? (
          <div className="tech-grid">
            <div>
              <dt>Key encapsulation</dt>
              <dd>{handshake.kem} (FIPS 203)</dd>
            </div>
            <div>
              <dt>Encapsulation key</dt>
              <dd>{handshake.kem_encaps_key_bytes} bytes</dd>
            </div>
            <div>
              <dt>KEM ciphertext</dt>
              <dd>{handshake.kem_ciphertext_bytes} bytes</dd>
            </div>
            <div>
              <dt>PQ shared secret</dt>
              <dd>{handshake.kem_shared_secret_bytes} bytes</dd>
            </div>
            <div>
              <dt>Classical exchange</dt>
              <dd>
                {handshake.classical} ({handshake.classical_shared_secret_bytes}-byte secret)
              </dd>
            </div>
            <div>
              <dt>KDF</dt>
              <dd>
                SHA-256("{handshake.kdf_label}" ‖ ss_pq ‖ ss_x25519)
              </dd>
            </div>
            <div>
              <dt>Session fingerprint</dt>
              <dd>{handshake.session_fingerprint}</dd>
            </div>
            <div>
              <dt>Handshake time</dt>
              <dd>{handshake.duration_ms.toFixed(3)} ms</dd>
            </div>
            <div className="tech-wide">
              <dt>Ciphertext (first 36 bytes, base64)</dt>
              <dd>{handshake.kem_ciphertext_preview}…</dd>
            </div>
          </div>
        ) : (
          <div className="empty">
            No active session — establish the quantum-safe session on the Shield tab to see live
            handshake parameters.
          </div>
        )}
      </section>

      <section className="tech-section">
        <h3>Applied migrations ({details.length})</h3>
        {details.length === 0 && (
          <div className="empty">
            Nothing migrated yet. Queue a finding on the Assets tab and apply it — the exact file
            change will be recorded here.
          </div>
        )}
        {details.map((d) => (
          <article className="tech-migration" key={d.finding_id}>
            <header>
              <span className="tech-id">{d.finding_id}</span>
              <span className="tech-when">
                {d.action} · {d.applied_at} UTC
              </span>
            </header>
            <p className="tech-summary">{d.summary}</p>
            {d.new_key_fingerprint && (
              <div className="tech-kv">
                <dt>Generated key</dt>
                <dd>
                  {d.new_key_path}
                  <br />
                  {d.new_key_fingerprint}
                </dd>
              </div>
            )}
            {d.file_path && (
              <>
                <div className="tech-kv">
                  <dt>File modified</dt>
                  <dd>{d.file_path}</dd>
                </div>
                <pre className="diff">
                  {lineDiff(d.before ?? "", d.after ?? "").map((op, idx) => (
                    <span key={idx} className={`diff-${op.type}`}>
                      {op.type === "add" ? "+ " : op.type === "del" ? "- " : "  "}
                      {op.text}
                      {"\n"}
                    </span>
                  ))}
                </pre>
              </>
            )}
            {!d.file_path && (
              <div className="tech-kv">
                <dt>Change type</dt>
                <dd>Policy setting in the local database — no files were modified.</dd>
              </div>
            )}
          </article>
        ))}
      </section>
    </div>
  );
}
