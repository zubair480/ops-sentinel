import {
  CheckCircle2,
  ChevronRight,
  GitBranch,
  GitPullRequest,
  RotateCcw,
  TerminalSquare,
} from "lucide-react";

export default function OpseraPipelineCard({ opsera, running }) {
  const payload = opsera?.request || {
    action: "PIPELINE_ROLLBACK",
    target_pipeline: "prod-auth-service",
    status: "ARMED",
    incident_hash: "awaiting-incident",
  };
  const response = opsera?.response;

  return (
    <section className="opsera-card panel">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">Automated mitigation</span>
          <h2>Opsera Forge</h2>
        </div>
        <span className={`forge-state ${response ? "triggered" : ""}`}>
          <i />
          {response ? "Triggered" : running ? "Preparing" : "Armed"}
        </span>
      </div>

      <div className="pipeline-flow">
        <div className={running || response ? "flow-node done" : "flow-node"}>
          <GitBranch size={15} />
          Detect
        </div>
        <ChevronRight size={14} />
        <div className={response ? "flow-node done" : "flow-node"}>
          <RotateCcw size={15} />
          Rollback
        </div>
        <ChevronRight size={14} />
        <div className={response ? "flow-node done" : "flow-node"}>
          <GitPullRequest size={15} />
          Stage PR
        </div>
      </div>

      <div className="payload-window">
        <div className="payload-title">
          <span>
            <TerminalSquare size={13} /> forge_payload.json
          </span>
          {response && (
            <span className="payload-valid">
              <CheckCircle2 size={12} /> verified
            </span>
          )}
        </div>
        <pre>
          {`{
  "action": "${payload.action}",
  "target": "${payload.target_pipeline}",
  "status": "${payload.status}",
  "incident": "${payload.incident_hash}"
}`}
        </pre>
      </div>

      <div className="forge-footer">
        <div>
          <span>Build ID</span>
          <strong>{response?.build_id || "—"}</strong>
        </div>
        <div>
          <span>Change control</span>
          <strong>{response ? "PR staged" : "Pending"}</strong>
        </div>
        <div>
          <span>Mode</span>
          <strong>{response?.mode === "live" ? "Live" : "Verified demo"}</strong>
        </div>
      </div>
    </section>
  );
}
