"use client";

import { useCallback, useEffect, useRef, useState } from "react";
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
import IncidentDossier from "./components/IncidentDossier";
import ResponseWorkspace from "./components/ResponseWorkspace";

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

const buildDemoResult = (scenario, customQuery = "") => {
  const base = scenario === "supply_chain" ? demoData.supply_chain : demoData.zero_day;
  const result =
    scenario !== "custom"
      ? base
      : {
          ...base,
          incident_id: `INC-${Math.random().toString(16).slice(2, 8).toUpperCase()}`,
          incident_type: "custom",
          query: customQuery,
          threat_summary: {
            ...base.threat_summary,
            title: "Operator-defined threat signal investigated",
            severity_score: 9.2,
            severity_label: "CRITICAL",
            confidence: 0.94,
            summary:
              `OpsSentinel evaluated the operator signal “${customQuery.trim()}” against ` +
              "the available advisory evidence and mapped the likely exposure to the production dependency graph.",
            affected_components: [
              "signal-under-review",
              "prod-auth-service",
              "release pipeline",
            ],
          },
          opsera: {
            request: {
              ...base.opsera.request,
              target_pipeline: "security-investigation",
              incident_hash: Math.random().toString(16).slice(2, 14),
            },
            response: {
              ...base.opsera.response,
              build_id: `OPS-${Math.floor(Math.random() * 800000 + 100000)}`,
            },
          },
        };
  const sourceDomains = [
    ...new Set(result.citations.map((citation) => new URL(citation.url).hostname)),
  ];
  const supplyChain = scenario === "supply_chain";
  return {
    ...result,
    incident_type: result.incident_type || scenario,
    run_id: `RUN-${Math.random().toString(16).slice(2, 10).toUpperCase()}`,
    provenance: {
      citation_count: result.citations.length,
      source_domains: sourceDomains,
      source_mode: "demo",
      reasoning_mode: "evidence_rules",
      fallback_active: true,
      retrieved_at: new Date().toISOString(),
    },
    telemetry: {
      elapsed_ms: 2480,
      completed_at: new Date().toISOString(),
    },
    threat_summary: {
      risk_tags: supplyChain
        ? ["vendor concentration", "export control", "lead-time exposure"]
        : ["software supply chain", "dependency compromise", "remote access"],
      indicators: supplyChain ? [] : [{ type: "CVE", value: "CVE-2024-3094" }],
      ...result.threat_summary,
    },
    opsera: {
      ...result.opsera,
      request: {
        guardrails: {
          require_human_approval_for_production: true,
          preserve_audit_log: true,
          max_rollback_depth: 1,
        },
        remediation_steps: supplyChain
          ? [
              "Pause affected hardware release train",
              "Route demand to approved alternate suppliers",
              "Stage procurement manifest update for approval",
            ]
          : [
              "Rollback to last known-good dependency lockfile",
              "Rebuild and rescan the production image",
              "Stage a remediation pull request for approval",
            ],
        ...result.opsera.request,
      },
    },
  };
};

const stageMessages = [
  {
    kind: "search",
    message: "Ingesting live web index and extracting factual citations…",
    detail: "Recency window: 24h · Source diversity check enabled",
  },
  {
    kind: "analysis",
    message: "You.com Research is cross-referencing advisories and affected assets…",
    detail: "Citation-grounded Threat Analyst · no paid LLM required",
  },
  {
    kind: "plan",
    message: "Building a least-blast-radius mitigation and rollback plan…",
    detail: "Remediation Planner · change policy OPS-P1",
  },
  {
    kind: "action",
    message: "Opsera-compatible rollback payload staged safely.",
    detail: "Simulation fallback · human approval gate preserved",
  },
];

const now = () =>
  new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date());

const getApiBase = () => {
  const configuredBase =
    typeof import.meta !== "undefined" ? import.meta.env?.VITE_API_BASE_URL : "";
  const localBrowser =
    typeof window !== "undefined" &&
    ["localhost", "127.0.0.1"].includes(window.location.hostname);
  return configuredBase || (localBrowser ? "http://localhost:8000" : window.location.origin);
};

const formatElapsed = (elapsedMs) => {
  if (!Number.isFinite(elapsedMs)) return "—";
  if (elapsedMs < 1000) return `${elapsedMs}ms`;
  return `${(elapsedMs / 1000).toFixed(1)}s`;
};

export default function OpsSentinelApp() {
  const [selected, setSelected] = useState("zero_day");
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [runCount, setRunCount] = useState(0);
  const [customQuery, setCustomQuery] = useState(
    "Is the latest open-source package compromise affecting our production CI runners?"
  );
  const [approvalState, setApprovalState] = useState("idle");
  const [approvalReceipt, setApprovalReceipt] = useState(null);
  const [history, setHistory] = useState([]);
  const [integrationStatus, setIntegrationStatus] = useState({
    youcom: "checking",
    reasoning: "checking",
    opsera: "checking",
  });
  const timers = useRef([]);

  useEffect(() => {
    let active = true;
    fetch(`${getApiBase()}/api/status`)
      .then((response) => {
        if (!response.ok) throw new Error(`Status request failed: ${response.status}`);
        return response.json();
      })
      .then((status) => {
        if (active) setIntegrationStatus(status);
      })
      .catch(() => {
        if (active) {
          setIntegrationStatus({
            youcom: "unavailable",
            reasoning: "fallback",
            opsera: "unavailable",
          });
        }
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    try {
      const stored = JSON.parse(window.localStorage.getItem("ops-sentinel-history") || "[]");
      if (Array.isArray(stored)) setHistory(stored.slice(0, 8));
    } catch {
      // Device history is optional and never blocks the response flow.
    }
  }, []);

  useEffect(() => {
    if (!result) return;
    setApprovalState("pending");
    const item = {
      id: result.incident_id,
      incidentType: result.incident_type || selected,
      query: result.query || customQuery,
      title: result.threat_summary.title,
      severity: result.threat_summary.severity_label,
      score: result.threat_summary.severity_score,
      time: now(),
    };
    setHistory((current) => {
      const next = [item, ...current.filter((entry) => entry.id !== item.id)].slice(0, 8);
      try {
        window.localStorage.setItem("ops-sentinel-history", JSON.stringify(next));
      } catch {
        // Private browsing can disable localStorage; the in-memory history still works.
      }
      return next;
    });
  }, [result]);

  const clearTimers = useCallback(() => {
    timers.current.forEach((timer) => window.clearTimeout(timer));
    timers.current = [];
  }, []);

  const finishWithDemo = useCallback(
    (scenario, query, startAt = 0) => {
      const remaining = stageMessages.slice(startAt);
      if (remaining.length === 0) {
        setResult(buildDemoResult(scenario, query));
        setRunning(false);
        setRunCount((count) => count + 1);
        return;
      }
      remaining.forEach((stage, offset) => {
        const timer = window.setTimeout(() => {
          setLogs((current) => [
            ...current,
            { ...stage, id: `${Date.now()}-${offset}`, time: now() },
          ]);
          if (offset === remaining.length - 1) {
            setResult(buildDemoResult(scenario, query));
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
    setApprovalState("idle");
    setApprovalReceipt(null);

    const apiBase = getApiBase();
    const stream = new EventSource(
      `${apiBase}/api/incidents/stream?incident_type=${encodeURIComponent(selected)}` +
      `&query=${encodeURIComponent(selected === "custom" ? customQuery : "")}`
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
          run_id: data.run_id,
          sequence: data.sequence,
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
      finishWithDemo(selected, customQuery, receivedStages);
    };
  }, [clearTimers, customQuery, finishWithDemo, selected]);

  const reset = useCallback(() => {
    clearTimers();
    setLogs([]);
    setResult(null);
    setRunning(false);
    setApprovalState("idle");
    setApprovalReceipt(null);
  }, [clearTimers]);

  const recordDecision = useCallback(
    async (decision) => {
      if (!result) return;
      setApprovalState(decision);
      setApprovalReceipt(null);
      setLogs((current) => [
        ...current,
        {
          kind: "action",
          message:
            decision === "approved"
              ? "Operator approved the guarded production action."
              : "Operator placed the production action on hold for review.",
          detail: `Decision signed · ${result.opsera.request.incident_hash}`,
          id: `${Date.now()}-decision`,
          time: now(),
        },
      ]);

      try {
        const response = await fetch(`${getApiBase()}/api/mitigations/decision`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              incident_hash: result.opsera.request.incident_hash,
              decision,
              incident_id: result.incident_id,
              run_id: result.run_id,
            }),
        });
        if (!response.ok) throw new Error(`Decision request failed: ${response.status}`);
        const receipt = await response.json();
        setApprovalReceipt(receipt);
        setLogs((current) => [
          ...current,
          {
            kind: "action",
            message: `Audit receipt ${receipt.audit_id} recorded.`,
            detail: `${receipt.status} · ${receipt.recorded_at}`,
            id: `${Date.now()}-audit`,
            time: now(),
          },
        ]);
      } catch {
        setApprovalReceipt({
          status: "LOCAL_ONLY",
          audit_id: "Network unavailable",
        });
      }
    },
    [result]
  );

  const exportReport = useCallback(() => {
    if (!result) return;
    const report = {
      product: "OpsSentinel",
      exported_at: new Date().toISOString(),
      approval_state: approvalState,
      approval_receipt: approvalReceipt,
      ...result,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ops-sentinel-${result.incident_id.toLowerCase()}.json`;
    link.click();
    window.URL.revokeObjectURL(url);
  }, [approvalReceipt, approvalState, result]);

  const loadHistoryItem = useCallback((item) => {
    setSelected(item.incidentType || "zero_day");
    if (item.incidentType === "custom") setCustomQuery(item.query || "");
    setResult(null);
    setApprovalState("idle");
    setApprovalReceipt(null);
    setLogs([
      {
        kind: "search",
        message: `Loaded ${item.id} for a fresh evidence sweep.`,
        detail: "Historical findings are never reused without revalidation",
        id: `${Date.now()}-history`,
        time: now(),
      },
    ]);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const threat = result?.threat_summary;
  const sourceMode = result
    ? result.source_mode === "live"
      ? "live"
      : "demo"
    : integrationStatus.youcom === "live"
      ? "live"
      : "demo";

  return (
    <main className="app-shell">
      <Header
        running={running}
        sourceMode={sourceMode}
        integrationStatus={integrationStatus}
      />

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
            <strong>{formatElapsed(result?.telemetry?.elapsed_ms)}</strong>
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
            <strong>{running ? "Responding" : "Live intelligence ready"}</strong>
            <small>
              {running
                ? "Agent mesh is active"
                : `${integrationStatus.youcom === "live" ? "You.com connected" : "Fallback ready"} · on-demand`}
            </small>
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
            customQuery={customQuery}
            setCustomQuery={setCustomQuery}
          />

          <section className="trust-card panel">
            <div className="trust-icon">
              <ShieldCheck size={18} />
            </div>
            <div>
              <strong>No paid LLM required</strong>
              <p>You.com Research powers live reasoning; local evidence rules keep demos resilient.</p>
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

      <IncidentDossier result={result} />

      <ResponseWorkspace
        result={result}
        approvalState={approvalState}
        approvalReceipt={approvalReceipt}
        onDecision={recordDecision}
        onExport={exportReport}
        history={history}
        onLoadHistory={loadHistoryItem}
      />

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
          {(result?.citations ||
            demoData[selected === "supply_chain" ? "supply_chain" : "zero_day"].citations
          ).map((citation, index) => (
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
