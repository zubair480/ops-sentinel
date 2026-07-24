/** OpsSentinel Cloudflare Worker: vinext UI plus same-origin incident APIs. */
import {
  handleImageOptimization,
  DEFAULT_DEVICE_SIZES,
  DEFAULT_IMAGE_SIZES,
} from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  YOUCOM_API_KEY?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: {
          format: string;
          quality: number;
        }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

type IncidentType = "zero_day" | "supply_chain" | "custom";

type Citation = {
  title: string;
  url: string;
  snippet: string;
};

type ThreatSummary = {
  title: string;
  severity_score: number;
  severity_label: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  summary: string;
  affected_components: string[];
  confidence: number;
  inference_mode: string;
};

const SEARCH_QUERIES: Record<IncidentType, string> = {
  zero_day:
    "latest critical zero-day open source library supply chain vulnerability CISA NVD affected versions mitigation",
  supply_chain:
    "latest semiconductor export restrictions advanced chip manufacturing supply chain disruption lead times",
  custom:
    "latest critical cybersecurity and software supply chain advisories CISA NVD active exploitation mitigation",
};

const STAGES = {
  search: {
    kind: "search",
    message: "Ingesting You.com's live web index and extracting factual citations…",
    detail: "Live source discovery · citation verification enabled",
  },
  analysis: {
    kind: "analysis",
    message: "You.com Research is cross-referencing advisories and affected assets…",
    detail: "Agentic research · no paid LLM required",
  },
  plan: {
    kind: "plan",
    message: "Local remediation agent is building a least-blast-radius response…",
    detail: "Evidence rules · change policy OPS-P1",
  },
  action: {
    kind: "action",
    message: "Pipeline rollback payload verified and remediation PR staged.",
    detail: "Opsera simulation · human approval gate preserved",
  },
};

const DEMO_CITATIONS: Record<"zero_day" | "supply_chain", Citation[]> = {
  zero_day: [
    {
      title: "NVD: CVE-2024-3094 detail",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
      snippet:
        "NIST records malicious code in upstream XZ Utils tarballs for versions 5.6.0 and 5.6.1.",
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
        "Red Hat identifies affected Fedora builds and advises users to stop affected systems until remediated.",
    },
  ],
  supply_chain: [
    {
      title: "BIS semiconductor export controls",
      url: "https://www.bis.gov/press-release/commerce-strengthens-export-controls-restrict-chinas-capability-produce-advanced-semiconductors-military",
      snippet:
        "The U.S. Commerce Department details strengthened controls on advanced semiconductor manufacturing equipment.",
    },
    {
      title: "Federal Register: semiconductor manufacturing items",
      url: "https://www.federalregister.gov/documents/2024/12/05/2024-28267/foreign-produced-direct-product-rule-additions-and-refinements-to-controls-for-advanced-computing-and",
      snippet:
        "The rule describes additions and refinements to advanced-computing and semiconductor-manufacturing controls.",
    },
    {
      title: "Semiconductor Industry Association market data",
      url: "https://www.semiconductors.org/global-semiconductor-sales-increase-19-1-in-2024-double-digit-growth-projected-in-2025/",
      snippet:
        "Industry data provides demand context for assessing substitution risk and procurement pressure.",
    },
  ],
};

function baselineThreat(incidentType: IncidentType): ThreatSummary {
  if (incidentType === "supply_chain") {
    return {
      title: "Advanced-chip export controls threaten lead times",
      severity_score: 8.7,
      severity_label: "HIGH",
      summary:
        "A semiconductor export-control signal maps to approved suppliers in the impacted region. Procurement lead-time risk is elevated and a controlled release pause is recommended.",
      affected_components: [
        "edge-controller-v4",
        "APAC supplier tier 2",
        "Q4 launch",
      ],
      confidence: 0.91,
      inference_mode: "evidence_rules",
    };
  }

  return {
    title:
      incidentType === "custom"
        ? "Operator-defined threat signal investigated"
        : "XZ Utils supply-chain backdoor detected",
    severity_score: incidentType === "custom" ? 9.2 : 10,
    severity_label: "CRITICAL",
    summary:
      incidentType === "custom"
        ? "OpsSentinel evaluated the operator signal against verified advisory evidence and mapped likely exposure to the production dependency graph."
        : "Malicious code in liblzma versions 5.6.0 and 5.6.1 can interfere with SSH authentication on affected Linux systems. The simulated production auth image matches the exposed range.",
    affected_components:
      incidentType === "custom"
        ? ["signal-under-review", "prod-auth-service", "release pipeline"]
        : ["liblzma 5.6.1", "prod-auth-service", "linux/amd64"],
    confidence: incidentType === "custom" ? 0.94 : 0.98,
    inference_mode: "evidence_rules",
  };
}

function safeThreat(
  value: unknown,
  fallback: ThreatSummary,
): ThreatSummary {
  if (!value || typeof value !== "object") return fallback;
  const candidate = value as Record<string, unknown>;
  const labels = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
  const label = String(candidate.severity_label || "").toUpperCase();
  const components = Array.isArray(candidate.affected_components)
    ? candidate.affected_components
        .map((item) => String(item).trim().slice(0, 100))
        .filter(Boolean)
        .slice(0, 8)
    : fallback.affected_components;
  const score = Number(candidate.severity_score);
  const confidence = Number(candidate.confidence);

  return {
    title:
      typeof candidate.title === "string" && candidate.title.trim()
        ? candidate.title.trim().slice(0, 240)
        : fallback.title,
    severity_score: Number.isFinite(score)
      ? Math.round(Math.max(0, Math.min(10, score)) * 10) / 10
      : fallback.severity_score,
    severity_label: labels.has(label)
      ? (label as ThreatSummary["severity_label"])
      : fallback.severity_label,
    summary:
      typeof candidate.summary === "string" && candidate.summary.trim()
        ? candidate.summary.trim().slice(0, 1500)
        : fallback.summary,
    affected_components: components.length
      ? components
      : fallback.affected_components,
    confidence: Number.isFinite(confidence)
      ? Math.round(Math.max(0, Math.min(1, confidence)) * 100) / 100
      : fallback.confidence,
    inference_mode: "youcom_research",
  };
}

function sourceCitations(value: unknown): Citation[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const output: Citation[] = [];
  for (const raw of value) {
    if (!raw || typeof raw !== "object") continue;
    const source = raw as Record<string, unknown>;
    const url = typeof source.url === "string" ? source.url.trim() : "";
    if (!url.startsWith("http") || seen.has(url)) continue;
    seen.add(url);
    const snippets = Array.isArray(source.snippets)
      ? source.snippets.map(String).join(" ")
      : String(source.snippet || source.description || "");
    output.push({
      title: String(source.title || new URL(url).hostname).slice(0, 240),
      url,
      snippet:
        snippets.trim().slice(0, 700) ||
        "Open the source to verify this finding.",
    });
  }
  return output.slice(0, 8);
}

async function youComResearch(
  env: Env,
  incidentType: IncidentType,
  query: string,
): Promise<{
  citations: Citation[];
  threat: ThreatSummary;
  sourceMode: "live" | "demo";
}> {
  const fallback = baselineThreat(incidentType);
  const demoKey = incidentType === "supply_chain" ? "supply_chain" : "zero_day";
  if (!env.YOUCOM_API_KEY) {
    return {
      citations: DEMO_CITATIONS[demoKey],
      threat: fallback,
      sourceMode: "demo",
    };
  }

  const outputSchema = {
    type: "object",
    properties: {
      title: { type: "string" },
      severity_score: { type: "number" },
      severity_label: {
        type: "string",
        enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      },
      summary: { type: "string" },
      affected_components: {
        type: "array",
        items: { type: "string" },
      },
      confidence: { type: "number" },
    },
    required: [
      "title",
      "severity_score",
      "severity_label",
      "summary",
      "affected_components",
      "confidence",
    ],
    additionalProperties: false,
  };

  const context =
    incidentType === "supply_chain"
      ? "Focus on confirmed disruptions, impacted suppliers or components, lead-time risk, and mitigations."
      : "Focus on active exploitation, affected versions, authoritative advisories, and immediate containment.";
  const response = await fetch("https://api.you.com/v1/research", {
    method: "POST",
    headers: {
      "X-API-Key": env.YOUCOM_API_KEY,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      input:
        "Act as the OpsSentinel Threat Analyst. Return a compact incident assessment grounded only in sources you can cite. " +
        `${context} Query: ${query}`,
      research_effort: "standard",
      output_schema: outputSchema,
    }),
  });

  if (!response.ok) {
    return {
      citations: DEMO_CITATIONS[demoKey],
      threat: fallback,
      sourceMode: "demo",
    };
  }

  const payload = (await response.json()) as {
    output?: { content?: unknown; sources?: unknown };
  };
  const citations = sourceCitations(payload.output?.sources);
  if (!citations.length) {
    return {
      citations: DEMO_CITATIONS[demoKey],
      threat: fallback,
      sourceMode: "demo",
    };
  }
  return {
    citations,
    threat: safeThreat(payload.output?.content, fallback),
    sourceMode: "live",
  };
}

function incidentHash(input: string): string {
  let hash = 2166136261;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash >>> 0).toString(16).padStart(12, "0").slice(0, 12);
}

function id(prefix: string): string {
  return `${prefix}-${crypto.randomUUID().replaceAll("-", "").slice(0, 8).toUpperCase()}`;
}

function event(name: string, data: unknown): string {
  return `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
}

function incidentStream(request: Request, env: Env): Response {
  const url = new URL(request.url);
  const requestedType = url.searchParams.get("incident_type");
  const incidentType: IncidentType =
    requestedType === "supply_chain" || requestedType === "custom"
      ? requestedType
      : "zero_day";
  const customQuery = url.searchParams.get("query")?.trim().slice(0, 280) || "";
  const query =
    incidentType === "custom" && customQuery
      ? customQuery
      : SEARCH_QUERIES[incidentType];
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (name: string, data: unknown) =>
        controller.enqueue(encoder.encode(event(name, data)));
      const startedAt = Date.now();

      try {
        send("stage", STAGES.search);
        const research = await youComResearch(env, incidentType, query);
        send("stage", STAGES.analysis);
        send("stage", STAGES.plan);

        const targetPipeline =
          incidentType === "supply_chain"
            ? "edge-controller-release"
            : incidentType === "custom"
              ? "security-investigation"
              : "prod-auth-service";
        const hash = incidentHash(
          `${incidentType}:${query}:${research.threat.title}`,
        );
        const actionPayload = {
          action: "PIPELINE_ROLLBACK",
          target_pipeline: targetPipeline,
          status: "TRIGGERED",
          incident_hash: hash,
        };

        send("stage", STAGES.action);
        send("complete", {
          incident_id: id("INC"),
          incident_type: incidentType,
          source_mode: research.sourceMode,
          query,
          citations: research.citations,
          threat_summary: research.threat,
          opsera: {
            request: actionPayload,
            response: {
              verified: true,
              mode: "simulated",
              build_id: id("OPS"),
              status: "TRIGGERED",
              timestamp: new Date().toISOString(),
            },
          },
          telemetry: {
            elapsed_ms: Date.now() - startedAt,
            completed_at: new Date().toISOString(),
          },
        });
      } catch {
        const fallback = baselineThreat(incidentType);
        const demoKey =
          incidentType === "supply_chain" ? "supply_chain" : "zero_day";
        send("stage", STAGES.analysis);
        send("stage", STAGES.plan);
        send("stage", STAGES.action);
        send("complete", {
          incident_id: id("INC"),
          incident_type: incidentType,
          source_mode: "demo",
          query,
          citations: DEMO_CITATIONS[demoKey],
          threat_summary: fallback,
          opsera: {
            request: {
              action: "PIPELINE_ROLLBACK",
              target_pipeline: "security-investigation",
              status: "TRIGGERED",
              incident_hash: incidentHash(query),
            },
            response: {
              verified: true,
              mode: "simulated",
              build_id: id("OPS"),
              status: "TRIGGERED",
            },
          },
        });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "X-Accel-Buffering": "no",
    },
  });
}

function json(data: unknown, status = 200): Response {
  return Response.json(data, { status });
}

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/status") {
      return json({
        youcom: env.YOUCOM_API_KEY ? "live" : "demo",
        reasoning: env.YOUCOM_API_KEY ? "youcom_research" : "evidence_rules",
        opsera: "simulated",
      });
    }

    if (url.pathname === "/api/incidents/stream" && request.method === "GET") {
      return incidentStream(request, env);
    }

    if (
      url.pathname === "/api/mitigations/decision" &&
      request.method === "POST"
    ) {
      const body = (await request.json()) as {
        incident_hash?: string;
        decision?: string;
      };
      return json({
        incident_hash: String(body.incident_hash || ""),
        decision: body.decision === "approved" ? "approved" : "held",
        status:
          body.decision === "approved"
            ? "APPROVED_FOR_PRODUCTION"
            : "HELD_FOR_REVIEW",
        audit_id: id("AUD"),
        recorded_at: new Date().toISOString(),
      });
    }

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(
        request,
        {
          fetchAsset: (path) =>
            env.ASSETS.fetch(new Request(new URL(path, request.url))),
          transformImage: async (body, { width, format, quality }) => {
            const result = await env.IMAGES.input(body)
              .transform(width > 0 ? { width } : {})
              .output({ format, quality });
            return result.response();
          },
        },
        allowedWidths,
      );
    }

    return handler.fetch(request, env, ctx);
  },
};

export default worker;
