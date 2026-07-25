import {
  Bot,
  Check,
  CircleDashed,
  Clock3,
  ExternalLink,
  GitPullRequestArrow,
  Search,
} from "lucide-react";

const meta = {
  search: { icon: Search, label: "YOU.COM SEARCH", tone: "cyan" },
  analysis: { icon: Bot, label: "YOU.COM RESEARCH · THREAT ANALYST", tone: "violet" },
  plan: { icon: GitPullRequestArrow, label: "LOCAL AGENT · REMEDIATION", tone: "amber" },
  action: { icon: Check, label: "OPSERA FORGE", tone: "green" },
};

export default function AgentLogStream({ logs, running }) {
  return (
    <section className="stream-card panel">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">Agent activity</span>
          <h2>Live execution stream</h2>
        </div>
        <span className={`live-chip ${running ? "active" : ""}`}>
          <i />
          {running ? "Live" : "Standby"}
        </span>
      </div>

      <div className="stream-body" aria-live="polite">
        {logs.length === 0 ? (
          <div className="empty-stream">
            <CircleDashed size={27} />
            <strong>Sentinel is watching</strong>
            <span>Choose a scenario to observe the agent handoffs.</span>
          </div>
        ) : (
          <ol className="timeline">
            {logs.map((log, index) => {
              const item = meta[log.kind] || meta.analysis;
              const Icon = item.icon;
              const isLatest = running && index === logs.length - 1;
              return (
                <li className={`timeline-item ${isLatest ? "latest" : ""}`} key={log.id}>
                  <div className={`timeline-icon ${item.tone}`}>
                    {isLatest ? <span className="mini-spinner" /> : <Icon size={15} />}
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-meta">
                      <span>
                        {item.label}
                        {log.run_id && (
                          <em className="run-correlation">
                            {log.run_id} / {String(log.sequence).padStart(2, "0")}
                          </em>
                        )}
                      </span>
                      <time>
                        <Clock3 size={11} />
                        {log.time}
                      </time>
                    </div>
                    <p>{log.message}</p>
                    {log.detail && <small>{log.detail}</small>}
                    {log.url && (
                      <a href={log.url} target="_blank" rel="noreferrer">
                        Verify source <ExternalLink size={11} />
                      </a>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </div>
    </section>
  );
}
