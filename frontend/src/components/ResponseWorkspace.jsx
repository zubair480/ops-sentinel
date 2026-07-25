import {
  Check,
  CircleDot,
  Clock3,
  Download,
  FileJson,
  GitCommitHorizontal,
  History,
  Network,
  Pause,
  ShieldCheck,
} from "lucide-react";

const fallbackComponents = ["source signal", "service dependency", "release pipeline"];

export default function ResponseWorkspace({
  result,
  approvalState,
  approvalReceipt,
  onDecision,
  onExport,
  history,
  onLoadHistory,
}) {
  const components =
    result?.threat_summary?.affected_components?.slice(0, 3) || fallbackComponents;
  const impactCount = result ? components.length : 0;

  return (
    <section className="response-workspace">
      <div className="workspace-heading">
        <div>
          <span className="section-kicker">Decision intelligence</span>
          <h2>Blast radius & control plane</h2>
        </div>
        <div className="workspace-summary">
          <span><CircleDot size={11} /> {impactCount} mapped components</span>
          <span><ShieldCheck size={11} /> Policy OPS-P1 enforced</span>
        </div>
      </div>

      <div className="workspace-grid">
        <section className="blast-card panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">Dependency graph</span>
              <h2>Predicted blast radius</h2>
            </div>
            <Network size={17} />
          </div>

          <div className={`blast-map ${result ? "active" : ""}`}>
            <div className="blast-source">
              <span className="map-pulse" />
              <strong>{result ? "Threat signal" : "Awaiting signal"}</strong>
              <small>{result?.incident_id || "No incident selected"}</small>
            </div>
            <div className="blast-rail" aria-hidden="true"><i /><i /><i /></div>
            <div className="blast-nodes" aria-label="Affected dependency nodes">
              {components.map((component, index) => (
                <div className={`blast-node level-${index + 1}`} key={component}>
                  <span><GitCommitHorizontal size={13} /></span>
                  <div>
                    <strong>{component}</strong>
                    <small>
                      {result
                        ? ["Direct exposure", "Transitive dependency", "Release impact"][index]
                        : "Not yet evaluated"}
                    </small>
                  </div>
                  <em>{result ? ["P0", "P1", "P1"][index] : "—"}</em>
                </div>
              ))}
            </div>
          </div>

          <div className="impact-metrics">
            <div><span>Affected components</span><strong>{result ? impactCount.toString().padStart(2, "0") : "00"}</strong></div>
            <div><span>Evidence sources</span><strong>{result?.citations?.length || "—"}</strong></div>
            <div><span>Risk score</span><strong>{result ? result.threat_summary.severity_score.toFixed(1) : "—"}</strong></div>
            <div><span>Rollback depth</span><strong>{result ? "1 build" : "—"}</strong></div>
          </div>
        </section>

        <div className="control-stack">
          <section className="approval-card panel">
            <div className="approval-heading">
              <span className={`approval-icon ${approvalState}`}>
                {approvalState === "approved" ? <Check size={17} /> : <Pause size={17} />}
              </span>
              <div>
                <span className="section-kicker">Human-in-the-loop gate</span>
                <h2>
                  {approvalState === "approved"
                    ? "Production action approved"
                    : approvalState === "held"
                      ? "Action held for review"
                      : "Approval required"}
                </h2>
              </div>
            </div>
            <p>
              Agents may stage a rollback and remediation PR autonomously. Production
              execution remains under operator control.
            </p>
            <div className="approval-actions">
              <button
                type="button"
                className="approve-button"
                onClick={() => onDecision("approved")}
                disabled={!result || approvalState !== "pending"}
              >
                <Check size={14} /> Approve production action
              </button>
              <button
                type="button"
                className="hold-button"
                onClick={() => onDecision("held")}
                disabled={!result || approvalState !== "pending"}
              >
                <Pause size={14} /> Hold
              </button>
            </div>
            <div className="approval-audit">
              <span>
                <Clock3 size={11} />
                {approvalReceipt?.audit_id || "Awaiting operator decision"}
              </span>
              <span>{approvalReceipt?.status || "Not signed"}</span>
            </div>
          </section>

          <section className="report-card panel">
            <div className="report-copy">
              <span><FileJson size={17} /></span>
              <div>
                <strong>Incident evidence package</strong>
                <small>Citations, agent findings, payload, and audit metadata</small>
              </div>
            </div>
            <button type="button" onClick={onExport} disabled={!result}>
              <Download size={14} /> Export JSON
            </button>
          </section>
        </div>

        <section className="history-card panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">This device</span>
              <h2>Response history</h2>
            </div>
            <History size={17} />
          </div>
          <div className="history-list">
            {history.length === 0 ? (
              <div className="history-empty">
                <Clock3 size={18} />
                <span>Completed investigations will be saved here.</span>
              </div>
            ) : (
              history.slice(0, 4).map((item) => (
                <button type="button" key={item.id} onClick={() => onLoadHistory(item)}>
                  <span className={`history-severity ${item.severity.toLowerCase()}`} />
                  <div>
                    <strong>{item.title}</strong>
                    <small>{item.id} · {item.time}</small>
                  </div>
                  <em>{item.score.toFixed(1)}</em>
                </button>
              ))
            )}
          </div>
        </section>
      </div>
    </section>
  );
}
