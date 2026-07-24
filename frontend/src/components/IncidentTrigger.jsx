import { AlertTriangle, Cpu, Play, RotateCcw, ShieldAlert } from "lucide-react";

const incidents = [
  {
    id: "zero_day",
    eyebrow: "Application security",
    title: "Zero-day in open-source library",
    detail: "Production auth service · Critical",
    icon: ShieldAlert,
  },
  {
    id: "supply_chain",
    eyebrow: "Supply chain",
    title: "Microchip export disruption",
    detail: "APAC hardware dependency · High",
    icon: Cpu,
  },
];

export default function IncidentTrigger({
  selected,
  setSelected,
  onRun,
  running,
  onReset,
}) {
  return (
    <section className="trigger-card panel">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">Judge simulation</span>
          <h2>Inject an incident</h2>
        </div>
        <AlertTriangle size={18} aria-hidden="true" />
      </div>

      <p className="panel-copy">
        Launch a safe, end-to-end response scenario. No production systems are
        touched in demo mode.
      </p>

      <div className="incident-options" role="radiogroup" aria-label="Incident scenario">
        {incidents.map(({ id, eyebrow, title, detail, icon: Icon }) => (
          <button
            className={`incident-option ${selected === id ? "selected" : ""}`}
            type="button"
            role="radio"
            aria-checked={selected === id}
            onClick={() => !running && setSelected(id)}
            key={id}
          >
            <span className="incident-icon">
              <Icon size={18} aria-hidden="true" />
            </span>
            <span>
              <small>{eyebrow}</small>
              <strong>{title}</strong>
              <em>{detail}</em>
            </span>
            <i className="radio-mark" />
          </button>
        ))}
      </div>

      <button
        className="run-button"
        type="button"
        onClick={onRun}
        disabled={running}
      >
        {running ? (
          <>
            <span className="button-spinner" />
            Response in progress
          </>
        ) : (
          <>
            <Play size={16} fill="currentColor" />
            Run autonomous response
          </>
        )}
      </button>

      <button className="reset-button" type="button" onClick={onReset} disabled={running}>
        <RotateCcw size={13} />
        Reset demonstration
      </button>
    </section>
  );
}
