import type { Finding, SampleId } from "./schemas.js";
import { getSample, SAMPLES } from "./samples.js";

const SQL_CONCAT = /(?:select|insert|update|delete|from|where)[\s\S]{0,80}['"`]\s*\+|concat\s*\([^)]*(?:select|from)/i;
const INNER_HTML = /\.innerHTML\s*([+]?=)|\bdocument\.write\s*\(/i;
const HARDCODED = /\b(api[_-]?key|secret|password|passwd|token|private[_-]?key)\b[^\n]{0,40}(=|:)\s*['"][^'"]{6,}['"]/i;
const PATH_JOIN = /path\.join\s*\(|fopen\s*\(|readFile(?:Sync)?\s*\(/i;

export function detectSample(code: string): SampleId | undefined {
  const trimmed = normalize(code);
  return SAMPLES.find((sample) => normalize(sample.code) === trimmed)?.id;
}

export function demoFindingsFor(code: string, sampleId?: SampleId): { summary: string; findings: Finding[] } {
  const id = sampleId ?? detectSample(code);
  if (id) {
    const sample = getSample(id);
    return { summary: sample.summary, findings: sample.findings.map((finding) => ({ ...finding })) };
  }
  return scanForDemoFindings(code);
}

export function scanForDemoFindings(code: string): { summary: string; findings: Finding[] } {
  const findings: Finding[] = [];
  const lines = code.split(/\r?\n/);

  for (const [index, line] of lines.entries()) {
    const number = index + 1;
    if (SQL_CONCAT.test(line) || /['"`]\s*\+\s*\w+/.test(line) && /(?:select|insert|update|delete|query)/i.test(line)) {
      findings.push({
        line: number,
        severity: "critical",
        cwe: "CWE-89",
        title: "Possible SQL concatenation",
        explanation:
          "This line looks like SQL is being built with string concatenation, which can let user input change the query.",
        fix: "Switch to parameterized queries or a query builder and keep untrusted values out of the SQL string.",
      });
    }
    if (INNER_HTML.test(line)) {
      findings.push({
        line: number,
        severity: "high",
        cwe: "CWE-79",
        title: "Possible unsafe HTML assignment",
        explanation:
          "Assigning untrusted data to innerHTML or document.write can run script in the page.",
        fix: "Use textContent or a vetted sanitizer, and treat all external strings as untrusted.",
      });
    }
    if (HARDCODED.test(line)) {
      findings.push({
        line: number,
        severity: "critical",
        cwe: "CWE-798",
        title: "Possible hardcoded secret",
        explanation:
          "A literal that looks like a key, token or password is present in the source. This is only a heuristic in demo mode.",
        fix: "Move secrets to environment variables or a secret manager and keep placeholders out of committed files.",
      });
    }
    if (PATH_JOIN.test(line) && /file|path|name|req\.|params|query|body/i.test(line)) {
      findings.push({
        line: number,
        severity: "high",
        cwe: "CWE-22",
        title: "Possible path traversal",
        explanation:
          "A file path is built from a value that may come from the user, without an obvious root check on this line.",
        fix: "Resolve the final path and ensure it stays inside an allowed directory before reading or writing the file.",
      });
    }
  }

  const unique = dedupe(findings);
  if (unique.length === 0) {
    return {
      summary: "Demo mode found no obvious SQL, XSS, secret or path-traversal patterns in this snippet.",
      findings: [],
    };
  }
  return {
    summary: `Demo mode flagged ${unique.length} pattern${unique.length === 1 ? "" : "s"} with a local heuristic, not a live model.`,
    findings: unique,
  };
}

function normalize(code: string): string {
  return code.replace(/\r\n/g, "\n").trim();
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.line}:${finding.cwe}:${finding.title}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }
  return result;
}
