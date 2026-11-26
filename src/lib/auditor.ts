import { parseJsonPayload } from "./json.js";
import { formatZodError, ModelAuditSchema, SEVERITY_RANK, type Finding, type ModelAudit } from "./schemas.js";

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const rank = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (rank !== 0) return rank;
    return a.line - b.line;
  });
}

export function lineCount(code: string): number {
  if (!code) return 0;
  return code.replace(/\n$/, "").split(/\r?\n/).length;
}

export function clampFindings(findings: Finding[], code: string): Finding[] {
  const last = Math.max(1, lineCount(code));
  return findings.map((finding) => ({
    ...finding,
    line: Math.min(Math.max(finding.line, 1), last),
  }));
}

export function parseModelAudit(text: string): ModelAudit {
  const parsed = ModelAuditSchema.safeParse(parseJsonPayload(text));
  if (!parsed.success) {
    throw new Error(formatZodError(parsed.error));
  }
  return parsed.data;
}

export function finalizeAudit(audit: ModelAudit, code: string): ModelAudit {
  return {
    summary: audit.summary,
    findings: sortFindings(clampFindings(audit.findings, code)),
  };
}

export async function completeJsonAudit(
  client: { complete(input: { system: string; user: string }): Promise<string> },
  input: { system: string; retrySystem: string; user: string },
): Promise<ModelAudit> {
  try {
    return parseModelAudit(await client.complete({ system: input.system, user: input.user }));
  } catch {
    return parseModelAudit(await client.complete({ system: input.retrySystem, user: input.user }));
  }
}
