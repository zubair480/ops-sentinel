import {
  Activity,
  Bot,
  Braces,
  Radio,
  Search,
  ShieldCheck,
} from "lucide-react";

const integrationPills = [
  { label: "You.com", icon: Search },
  { label: "Parasail", icon: Bot },
  { label: "Opsera", icon: Braces },
];

export default function Header({ running, sourceMode = "demo" }) {
  return (
    <header className="topbar">
      <div className="brand-lockup">
        <div className="brand-mark" aria-hidden="true">
          <ShieldCheck size={19} strokeWidth={2.2} />
        </div>
        <div>
          <div className="brand-row">
            <span className="brand-name">OpsSentinel</span>
            <span className="version-chip">v1.0</span>
          </div>
          <p>Autonomous incident response</p>
        </div>
      </div>

      <div className="header-center" aria-label="Integration status">
        {integrationPills.map(({ label, icon: Icon }) => (
          <div className="integration-pill" key={label}>
            <Icon size={13} aria-hidden="true" />
            <span>{label}</span>
            <i className="status-dot" />
          </div>
        ))}
      </div>

      <div className="system-state">
        <div className={`state-orb ${running ? "is-running" : ""}`}>
          {running ? <Activity size={15} /> : <Radio size={15} />}
        </div>
        <div>
          <span>{running ? "Agents deployed" : "System nominal"}</span>
          <small>{sourceMode === "live" ? "Live intelligence" : "Demo-ready mode"}</small>
        </div>
      </div>
    </header>
  );
}
