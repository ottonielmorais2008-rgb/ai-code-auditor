import { useMemo, useState } from "react";
import { demoFindingsFor } from "./lib/demo";
import { finalizeAudit } from "./lib/auditor";
import { SAMPLES } from "./lib/samples";
import type { AuditResult, Finding, SampleId, Severity } from "./lib/schemas";

const SOURCE_URL = "https://github.com/ottonielmorais2008-rgb/ai-code-auditor";
const DEFAULT_SAMPLE = SAMPLES[0]!;

function sampleResult(id: SampleId): AuditResult {
  const sample = SAMPLES.find((item) => item.id === id) ?? DEFAULT_SAMPLE;
  const audit = finalizeAudit(demoFindingsFor(sample.code, sample.id), sample.code);
  return {
    ...audit,
    mode: "sample",
    language: sample.language,
    source: "sample",
    sourceLabel: sample.filename,
    notice: "This is a canned sample with known issues. It does not call the model.",
  };
}

function highestSeverity(findings: Finding[], line: number): Severity | undefined {
  const matches = findings.filter((finding) => finding.line === line);
  return matches[0]?.severity;
}

function severityCounts(findings: Finding[]): Record<Severity, number> {
  return findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

export function App() {
  const [tab, setTab] = useState<"paste" | "url">("paste");
  const [sampleId, setSampleId] = useState<SampleId>(DEFAULT_SAMPLE.id);
  const [code, setCode] = useState(DEFAULT_SAMPLE.code);
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AuditResult>(() => sampleResult(DEFAULT_SAMPLE.id));
  const [activeLine, setActiveLine] = useState<number | null>(DEFAULT_SAMPLE.findings[0]?.line ?? null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lines = useMemo(() => code.replace(/\n$/, "").split("\n"), [code]);
  const counts = severityCounts(result.findings);

  function loadSample(id: SampleId) {
    const sample = SAMPLES.find((item) => item.id === id) ?? DEFAULT_SAMPLE;
    const next = sampleResult(sample.id);
    setSampleId(sample.id);
    setTab("paste");
    setCode(sample.code);
    setUrl("");
    setResult(next);
    setActiveLine(next.findings[0]?.line ?? null);
    setError(null);
  }

  function showResult(next: AuditResult, nextCode: string) {
    setCode(nextCode);
    setResult(next);
    setActiveLine(next.findings[0]?.line ?? null);
  }

  async function audit(mode: "live" | "demo") {
    setBusy(true);
    setError(null);
    try {
      const payload =
        tab === "url"
          ? { url, mode }
          : { code, mode, sampleId: sampleId && code === SAMPLES.find((s) => s.id === sampleId)?.code ? sampleId : undefined };
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = (await response.json()) as AuditResult & { error?: string };
      if (!response.ok) {
        setError(body.error ?? "The audit could not be completed.");
        return;
      }
      showResult(body, body.code ?? code);
    } catch {
      setError("The auditor is unavailable right now.");
    } finally {
      setBusy(false);
    }
  }

  function selectFinding(finding: Finding) {
    setActiveLine(finding.line);
    document.getElementById(`line-${finding.line}`)?.scrollIntoView({ block: "center", behavior: "smooth" });
  }

  return (
    <main className="page">
      <header className="hero">
        <div className="brand">
          <div className="logo" aria-hidden="true">
            {"{!}"}
          </div>
          <div>
            <h1>AI Code Auditor</h1>
            <p className="tagline">
              Paste source or a public GitHub file URL. Findings come back as validated JSON: line, severity, CWE and a
              suggested fix.
            </p>
          </div>
        </div>
        <div className="badges">
          <span className="badge">React + Zod</span>
          <span className="badge">Gemini optional</span>
          <a className="badge link" href={SOURCE_URL} target="_blank" rel="noreferrer">
            Source
          </a>
        </div>
      </header>

      <section className="panel form">
        <div className="tabs" role="tablist" aria-label="Input source">
          <button className={tab === "paste" ? "tab active" : "tab"} onClick={() => setTab("paste")} type="button">
            Paste code
          </button>
          <button className={tab === "url" ? "tab active" : "tab"} onClick={() => setTab("url")} type="button">
            GitHub URL
          </button>
        </div>
        {tab === "paste" ? (
          <label>
            Source
            <textarea value={code} onChange={(event) => setCode(event.target.value)} spellCheck={false} />
          </label>
        ) : (
          <label>
            Public GitHub file URL
            <input
              type="url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://github.com/owner/repo/blob/main/src/app.js"
            />
          </label>
        )}
        <div className="form-row">
          <div className="chips" aria-label="Vulnerable samples">
            {SAMPLES.map((sample) => (
              <button
                key={sample.id}
                type="button"
                className={sampleId === sample.id && tab === "paste" ? "chip active" : "chip"}
                onClick={() => loadSample(sample.id)}
              >
                {sample.title}
              </button>
            ))}
          </div>
          <div className="actions">
            <button type="button" className="primary" disabled={busy} onClick={() => void audit("live")}>
              {busy ? "Auditing…" : "Audit code"}
            </button>
            <button type="button" disabled={busy} onClick={() => void audit("demo")}>
              Use demo findings
            </button>
          </div>
        </div>
        {result.notice ? <p className="banner">{result.notice}</p> : null}
        {error ? <p className="banner error">{error}</p> : null}
      </section>

      <div className="layout">
        <section className="panel">
          <div className="panel-head">
            <h2>{result.sourceLabel ?? "Source"}</h2>
            <span className="muted small">{lines.length} lines</span>
          </div>
          <div className="code-view" role="table" aria-label="Source with finding highlights">
            {lines.map((line, index) => {
              const number = index + 1;
              const severity = highestSeverity(result.findings, number);
              return (
                <div
                  id={`line-${number}`}
                  key={number}
                  className={activeLine === number ? "code-line active" : "code-line"}
                  data-severity={severity}
                >
                  <span className="gutter">{number}</span>
                  <span className="code-text">{line || " "}</span>
                </div>
              );
            })}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Findings</h2>
            <div className="counts">
              <span className="badge sev-critical">{counts.critical} critical</span>
              <span className="badge sev-high">{counts.high} high</span>
              <span className="badge sev-medium">{counts.medium} medium</span>
              <span className="badge sev-low">{counts.low} low</span>
            </div>
          </div>
          <p className="muted small">{result.summary}</p>
          {result.findings.length === 0 ? (
            <p className="muted">No findings for this snippet.</p>
          ) : (
            <ul className="findings">
              {result.findings.map((finding, index) => (
                <li key={`${finding.line}-${finding.cwe}-${index}`}>
                  <button type="button" className={`finding sev-${finding.severity}`} onClick={() => selectFinding(finding)}>
                    <div className={`meta sev-${finding.severity}`}>
                      <span>{finding.severity}</span>
                      <span>{finding.cwe}</span>
                      <span>Line {finding.line}</span>
                    </div>
                    <h3>{finding.title}</h3>
                    <p>{finding.explanation}</p>
                    <p className="fix">
                      <strong>Fix:</strong> {finding.fix}
                    </p>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="fineprint">
        <p>
          Sample snippets are intentionally vulnerable. The live path calls Gemini from a serverless function; the key
          never ships to the browser. If the key is missing or the model fails, a deterministic demo still runs.
        </p>
        <p>
          Public GitHub files are fetched server-side, only from <code>raw.githubusercontent.com</code>, with a size
          limit. This is an educational demo, not a complete security review.
        </p>
      </section>
    </main>
  );
}
