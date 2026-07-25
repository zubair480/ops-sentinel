import {
  CheckCircle2,
  DatabaseZap,
  Fingerprint,
  ListChecks,
  Radar,
  ShieldCheck,
} from "lucide-react";

const EmptyState = ({ children }) => (
  <div className="dossier-empty">
    <Radar size={16} />
    <span>{children}</span>
  </div>
);

export default function IncidentDossier({ result }) {
  const provenance = result?.provenance;
  const indicators = result?.threat_summary?.indicators || [];
  const riskTags = result?.threat_summary?.risk_tags || [];
  const action = result?.opsera?.request;
  const steps = action?.remediation_steps || [];
  const guardrails = action?.guardrails;

  return (
    <section className="dossier-section">
      <div className="workspace-heading">
        <div>
          <span className="section-kicker">Incident dossier</span>
          <h2>Evidence, observables & response plan</h2>
        </div>
        <div className="workspace-summary">
          <span>
            <Fingerprint size={11} />
            {result?.run_id || "Run not started"}
          </span>
          <span>
            <ShieldCheck size={11} />
            {provenance?.fallback_active ? "Fallback evidence" : "Source-grounded"}
          </span>
        </div>
      </div>

      <div className="dossier-grid">
        <section className="dossier-card panel">
          <div className="dossier-title">
            <DatabaseZap size={16} />
            <div>
              <span>Evidence provenance</span>
              <strong>Retrieval chain</strong>
            </div>
          </div>
          {provenance ? (
            <>
              <dl className="dossier-facts">
                <div>
                  <dt>Sources</dt>
                  <dd>{provenance.citation_count}</dd>
                </div>
                <div>
                  <dt>Retrieval</dt>
                  <dd>{provenance.source_mode}</dd>
                </div>
                <div>
                  <dt>Inference</dt>
                  <dd>{provenance.reasoning_mode.replaceAll("_", " ")}</dd>
                </div>
              </dl>
              <div className="domain-cloud">
                {provenance.source_domains.map((domain) => (
                  <span key={domain}>{domain}</span>
                ))}
              </div>
            </>
          ) : (
            <EmptyState>Run an investigation to build provenance.</EmptyState>
          )}
        </section>

        <section className="dossier-card panel">
          <div className="dossier-title">
            <Radar size={16} />
            <div>
              <span>Extracted observables</span>
              <strong>Evidence-only indicators</strong>
            </div>
          </div>
          {result ? (
            <>
              <div className="indicator-list">
                {indicators.length ? (
                  indicators.map((indicator) => (
                    <span key={`${indicator.type}-${indicator.value}`}>
                      <em>{indicator.type}</em>
                      {indicator.value}
                    </span>
                  ))
                ) : (
                  <small>No CVE identifier was present in cited evidence.</small>
                )}
              </div>
              <div className="risk-tags">
                {riskTags.map((tag) => (
                  <span key={tag}>{tag}</span>
                ))}
              </div>
            </>
          ) : (
            <EmptyState>Observables appear only when supported by evidence.</EmptyState>
          )}
        </section>

        <section className="dossier-card playbook-card panel">
          <div className="dossier-title">
            <ListChecks size={16} />
            <div>
              <span>Remediation playbook</span>
              <strong>{action?.target_pipeline || "Awaiting target"}</strong>
            </div>
          </div>
          {steps.length ? (
            <>
              <ol className="playbook-steps">
                {steps.map((step, index) => (
                  <li key={step}>
                    <span>{index + 1}</span>
                    <p>{step}</p>
                  </li>
                ))}
              </ol>
              <div className="policy-checks">
                <span>
                  <CheckCircle2 size={11} />
                  Human approval
                </span>
                <span>
                  <CheckCircle2 size={11} />
                  Audit preserved
                </span>
                <span>
                  <CheckCircle2 size={11} />
                  Depth {guardrails?.max_rollback_depth ?? 1}
                </span>
              </div>
            </>
          ) : (
            <EmptyState>A constrained playbook will be generated after analysis.</EmptyState>
          )}
        </section>
      </div>
    </section>
  );
}
