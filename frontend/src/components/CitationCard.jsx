import { ArrowUpRight, CheckCircle2, Globe2 } from "lucide-react";

export default function CitationCard({ citation, index }) {
  let host = "Verified source";
  try {
    host = new URL(citation.url).hostname.replace("www.", "");
  } catch {
    // The backend already validates URLs; this keeps demo data resilient.
  }

  return (
    <a className="citation-card" href={citation.url} target="_blank" rel="noreferrer">
      <div className="citation-top">
        <span className="source-index">0{index + 1}</span>
        <span className="verified-badge">
          <CheckCircle2 size={11} />
          Live citation
        </span>
        <ArrowUpRight className="citation-arrow" size={16} />
      </div>
      <h3>{citation.title}</h3>
      <p>{citation.snippet}</p>
      <div className="citation-host">
        <Globe2 size={12} />
        {host}
      </div>
    </a>
  );
}
