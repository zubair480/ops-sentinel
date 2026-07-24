"use client";

import { useCallback, useRef, useState } from "react";
import {
  AlertOctagon,
  CheckCircle2,
  ChevronRight,
  Clock3,
  RadioTower,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import Header from "./components/Header";
import IncidentTrigger from "./components/IncidentTrigger";
import AgentLogStream from "./components/AgentLogStream";
import CitationCard from "./components/CitationCard";
import OpseraPipelineCard from "./components/OpseraPipelineCard";

const demoData = {
  zero_day: {
    incident_id: "INC-7F3A91",
    source_mode: "demo",
    threat_summary: {
      title: "XZ Utils supply-chain backdoor detected",
      severity_score: 10,
      severity_label: "CRITICAL",
      summary:
        "Malicious code in liblzma versions 5.6.0 and 5.6.1 can interfere with SSH authentication on affected Linux systems. The production auth image matches the exposed dependency range.",
      affected_components: ["liblzma 5.6.1", "prod-auth-service", "linux/amd64"],
      confidence: 0.98,
    },
    citations: [
      {
        title: "NVD: CVE-2024-3094 detail",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        snippet:
          "NIST records the malicious code discovered in the upstream XZ Utils tarballs for versions 5.6.0 and 5.6.1.",
      },
      {
        title: "CISA alert: XZ Utils supply-chain compromise",
        url: "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094",
        snippet:
          "CISA recommends downgrading XZ Utils and hunting for affected versions after the reported compromise.",
      },
      {
        title: "Red Hat urgent security alert",
        url: "https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users",
        snippet:
          "Red Hat identifies the affected Fedora builds and advises users to stop affected systems until remediated.",
      },
    ],
    opsera: {
      request: {
        action: "PIPELINE_ROLLBACK",
        target_pipeline: "prod-auth-service",
        status: "TRIGGERED",
        incident_hash: "7f3a91c2d8e4",
      },
      response: {
        verified: true,
        mode: "simulated",
        build_id: "OPS-845291",
        status: "TRIGGERED",
      },
    },
  },
  supply_chain: {
    incident_id: "INC-A42C18",
    source_mode: "demo",
    threat_summary: {
      title: "Advanced-chip export controls threaten lead times",
      severity_score: 8.7,
      severity_label: "HIGH",
      summary:
        "A new export-control signal affects advanced semiconductor manufacturing equipment. Two approved suppliers map to the impacted region, raising projected controller lead time from 8 to 21 weeks.",
      affected_components: ["edge-controller-v4", "APAC supplier tier 2", "Q4 launch"],
      confidence: 0.91,
    },
    citations: [
      {
        title: "BIS semiconductor export controls",
        url: "https://www.bis.gov/press-release/commerce-strengthens-export-controls-restrict-chinas-capability-produce-advanced-semiconductors-military",
        snippet:
          "The U.S. Commerce Department details strengthened controls on advanced semiconductor manufacturing equipment and related technology.",
      },
      {
        title: "Federal Register: semiconductor manufacturing items",
        url: "https://www.federalregister.gov/documents/2024/12/05/2024-28267/foreign-produced-direct-product-rule-additions-and-refinements-to-controls-for-advanced-computing-and",
        snippet:
          "The rule describes additions and refinements to controls for advanced computing and semiconductor manufacturing equipment.",
      },
      {
        title: "Semiconductor Industry Association market data",
        url: "https://www.semiconductors.org/global-semiconductor-sales-increase-19-1-in-2024-double-digit-growth-projected-in-2025/",
        snippet:
          "Industry data provides the demand context used to assess substitution risk and procurement pressure.",
      },
    ],
    opsera: {
      request: {
        action: "PIPELINE_ROLLBACK",
        target_pipeline: "edge-controller-release",
        status: "TRIGGERED",
        incident_hash: "a42c187d11f9",
      },
      response: {
        verified: true,
        mode: "simulated",
        build_id: "OPS-845447",
        status: "TRIGGERED",
      },
    },
  },
};

const stageMessages = [
  {
    kind: "search",
    message: "Ingesting live web index and extracting factual citations…",
    detail: "Recency window: 24h · Source diversity check enabled",
  },
  {
    kind: "analysis",
    message: "Cross-referencing advisories against the production dependency graph…",
    detail: "Threat Analyst · evidence confidence scoring",
  },
  {
    kind: "plan",
    message: "Building a least-blast-radius mitigation and rollback plan…",
    detail: "Remediation Planner · change policy OPS-P1",
  },
  {
    kind: "action",
    message: "Pipeline rollback triggered and remediation PR staged.",
    detail: "Verified payload · human approval gate preserved",
  },
];

const now = () =>
  new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date());

export default function OpsSentinelApp() {
  const [selected, setSelected] = useState("zero_day");
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [runCount, setRunCount] = useState(0);
  const timers = useRef([]);

  const clearTimers = useCallback(() => {
    timers.current.forEach((timer) => window.clearTimeout(timer));
    timers.current = [];
  }, []);

  const finishWithDemo = useCallback(
    (scenario, startAt = 0) => {
      const remaining = stageMessages.slice(startAt);
      remaining.forEach((stage, offset) => {
        const timer = window.setTimeout(() => {
          setLogs((current) => [
            ...current,
            { ...stage, id: `${Date.now()}-${offset}`, time: now() },
          ]);
          if (offset === remaining.length - 1) {
            setResult(demoData[scenario]);
            setRunning(false);
            setRunCount((count) => count + 1);
          }
        }, 620 * (offset + 1));
        timers.current.push(timer);
      });
    },
    []
  );

  const runIncident = useCallback(() => {
    clearTimers();
    setRunning(true);
    setLogs([]);
    setResult(null);

    const configuredBase =
      typeof import.meta !== "undefined" ? import.meta.env?.VITE_API_BASE_URL : "";
    const localBrowser =
      typeof window !== "undefined" &&
      ["localhost", "127.0.0.1"].includes(window.location.hostname);

    if (!configuredBase && !localBrowser) {
      finishWithDemo(selected);
      return;
    }

    const apiBase = configuredBase || "http://localhost:8000";
    const stream = new EventSource(
      `${apiBase}/api/incidents/stream?incident_type=${encodeURIComponent(selected)}`
    );
    let receivedStages = 0;

    stream.addEventListener("stage", (event) => {
      const data = JSON.parse(event.data);
      receivedStages += 1;
      setLogs((current) => [
        ...current,
        {
          kind: data.kind,
          message: data.message,
          detail: data.detail,
          id: `${Date.now()}-${receivedStages}`,
          time: now(),
        },
      ]);
    });

    stream.addEventListener("complete", (event) => {
      setResult(JSON.parse(event.data));
      setRunning(false);
      setRunCount((count) => count + 1);
      stream.close();
    });

    stream.onerror = () => {
      stream.close();
      finishWithDemo(selected, receivedStages);
    };
  }, [clearTimers, finishWithDemo, selected]);

  const reset = useCallback(() => {
    clearTimers();
    setLogs([]);
    setResult(null);
    setRunning(false);
  }, [clearTimers]);

  const threat = result?.threat_summary;
  const sourceMode = result?.source_mode === "live" ? "live" : "demo";

  return (
    <main className="app-shell">
      <Header running={running} sourceMode={sourceMode} />

      <div className="command-strip">
        <div className="command-title">
          <span className="command-icon">
            <RadioTower size={18} />
          </span>
          <div>
            <span>Mission control</span>
            <h1>Incident response cockpit</h1>
          </div>
        </div>
        <div className="command-stats">
          <div>
            <span>Time to contain</span>
            <strong>{result ? "02m 41s" : "—"}</strong>
          </div>
          <div>
            <span>Confidence</span>
            <strong>{threat ? `${Math.round(threat.confidence * 100)}%` : "—"}</strong>
          </div>
          <div>
            <span>Automations</span>
            <strong>{runCount.toString().padStart(2, "0")}</strong>
          </div>
        </div>
        <div className="watching-state">
          <span className="radar">
            <i />
          </span>
          <div>
            <strong>{running ? "Responding" : "Watching 3,248 assets"}</strong>
            <small>{running ? "Agent mesh is active" : "Last sweep 12 seconds ago"}</small>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        <aside className="left-rail">
          <IncidentTrigger
            selected={selected}
            setSelected={setSelected}
            onRun={runIncident}
            running={running}
            onReset={reset}
          />

          <section className="trust-card panel">
            <div className="trust-icon">
              <ShieldCheck size={18} />
            </div>
            <div>
              <strong>Demo-safe by design</strong>
              <p>Webhook calls are simulated until an Opsera URL is configured.</p>
            </div>
          </section>
        </aside>

        <section className="main-stage">
          <AgentLogStream logs={logs} running={running} />

          <section className={`finding-card panel ${threat ? "revealed" : ""}`}>
            <div className="finding-header">
              <div>
                <span className="section-kicker">Current finding</span>
                <h2>{threat?.title || "No active incident"}</h2>
              </div>
              <div className={`severity-score ${threat ? "visible" : ""}`}>
                <AlertOctagon size={17} />
                <span>{threat?.severity_label || "CLEAR"}</span>
                <strong>{threat?.severity_score?.toFixed(1) || "0.0"}</strong>
              </div>
            </div>
            {threat ? (
              <>
                <p className="finding-summary">{threat.summary}</p>
                <div className="component-row">
                  <span>Affected</span>
                  {threat.affected_components.map((component) => (
                    <em key={component}>{component}</em>
                  ))}
                </div>
              </>
            ) : (
              <div className="finding-placeholder">
                <Sparkles size={16} />
                Evidence-backed findings will appear here after analysis.
              </div>
            )}
          </section>
        </section>

        <aside className="right-rail">
          <OpseraPipelineCard opsera={result?.opsera} running={running} />

          <section className="audit-card panel">
            <div className="audit-line">
              <CheckCircle2 size={15} />
              <div>
                <strong>Policy guardrail</strong>
                <span>Human approval retained</span>
              </div>
              <ChevronRight size={14} />
            </div>
            <div className="audit-line">
              <Clock3 size={15} />
              <div>
                <strong>Audit trail</strong>
                <span>Every agent action signed</span>
              </div>
              <ChevronRight size={14} />
            </div>
          </section>
        </aside>
      </div>

      <section className="evidence-section">
        <div className="evidence-heading">
          <div>
            <span className="section-kicker">Evidence layer</span>
            <h2>Verified live intelligence</h2>
          </div>
          <p>
            Every material claim is linked to its source. Citations refresh when
            a live You.com key is connected.
          </p>
        </div>
        <div className="citation-grid">
          {(result?.citations || demoData[selected].citations).map((citation, index) => (
            <CitationCard citation={citation} index={index} key={citation.url} />
          ))}
        </div>
      </section>

      <footer>
        <span>
          <ShieldCheck size={14} /> OpsSentinel
        </span>
        <p>Built for the You.com Agentic Hackathon · AWS Builder Loft SF</p>
        <small>Search → reason → remediate</small>
      </footer>
    </main>
  );
}
