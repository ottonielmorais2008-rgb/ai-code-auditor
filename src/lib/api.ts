import { completeJsonAudit, finalizeAudit } from "./auditor.js";
import { demoFindingsFor } from "./demo.js";
import { createGeminiClient, getGeminiApiKey, getModelId, type EnvMap, type LlmClient } from "./gemini.js";
import { cors, methodOf, readJsonBody, tooLarge, type HttpRequest, type HttpResponse } from "./http.js";
import { AUDIT_SYSTEM, buildUserPrompt, RETRY_SYSTEM } from "./prompts.js";
import { allow, clientIp } from "./rate-limit.js";
import { getSample } from "./samples.js";
import { parseAuditInput, type AuditInput, type AuditResult, type RunMode } from "./schemas.js";
import { fetchPublicGitHubFile } from "./url.js";

export const AUDIT_LIMIT = 6;
export const AUDIT_WINDOW_MS = 60_000;

export interface AuditDeps {
  env?: EnvMap;
  client?: LlmClient;
  fetchFn?: typeof fetch;
  now?: number;
}

export function resolveMode(
  requested: unknown,
  hasKey: boolean,
): { mode: Exclude<RunMode, "sample">; notice?: string; useMock: boolean } {
  if (requested === "demo") {
    return { mode: "demo", useMock: true, notice: "Demo mode used local findings, not the live model." };
  }
  if (requested === "live" || requested == null || requested === "") {
    if (!hasKey) {
      return {
        mode: "demo",
        useMock: true,
        notice: "No API key is configured, so this audit used the built-in demo findings.",
      };
    }
    return { mode: "live", useMock: false };
  }
  return { mode: "demo", useMock: true, notice: "Unknown mode; falling back to the built-in demo findings." };
}

async function resolveSource(
  input: AuditInput,
  fetchFn: typeof fetch,
): Promise<
  | { ok: true; code: string; source: AuditResult["source"]; sourceLabel?: string; language?: AuditInput["language"] }
  | { ok: false; status: number; error: string }
> {
  if (input.sampleId && !input.url && !(input.code && input.code.trim())) {
    const sample = getSample(input.sampleId);
    return {
      ok: true,
      code: sample.code,
      source: "sample",
      sourceLabel: sample.filename,
      language: input.language ?? sample.language,
    };
  }
  if (input.url) {
    const fetched = await fetchPublicGitHubFile(input.url, fetchFn);
    if (!fetched.ok) return fetched;
    return {
      ok: true,
      code: fetched.code,
      source: "url",
      sourceLabel: fetched.label,
      language: input.language,
    };
  }
  const code = input.code?.trim() ?? "";
  if (!code) {
    return { ok: false, status: 400, error: "Paste some source, provide a public GitHub file URL, or choose a sample." };
  }
  return {
    ok: true,
    code,
    source: input.sampleId ? "sample" : "paste",
    sourceLabel: input.sampleId ? getSample(input.sampleId).filename : undefined,
    language: input.language,
  };
}

export async function executeAudit(
  input: unknown,
  deps: AuditDeps = {},
): Promise<{ ok: true; result: AuditResult } | { ok: false; status: number; error: string }> {
  const parsed = parseAuditInput(input);
  if (!parsed.ok) return { ok: false, status: 400, error: parsed.error };

  const env = deps.env ?? process.env;
  const apiKey = getGeminiApiKey(env);
  const resolved = resolveMode(parsed.value.mode, Boolean(apiKey));
  const source = await resolveSource(parsed.value, deps.fetchFn ?? fetch);
  if (!source.ok) return source;

  const finish = (audit: { summary: string; findings: ReturnType<typeof demoFindingsFor>["findings"] }, mode: RunMode, notice?: string): AuditResult => {
    const finalized = finalizeAudit(audit, source.code);
    return {
      ...finalized,
      mode,
      language: source.language,
      source: source.source,
      sourceLabel: source.sourceLabel,
      notice,
      code: source.code,
    };
  };

  const demo = () =>
    finish(demoFindingsFor(source.code, parsed.value.sampleId), "demo", resolved.useMock ? resolved.notice : undefined);

  if (resolved.useMock) {
    return { ok: true, result: demo() };
  }

  const client = deps.client ?? createGeminiClient(apiKey!, getModelId(env));
  try {
    const modelAudit = await completeJsonAudit(client, {
      system: AUDIT_SYSTEM,
      retrySystem: RETRY_SYSTEM,
      user: buildUserPrompt(source.code, source.language, source.sourceLabel),
    });
    return { ok: true, result: finish(modelAudit, "live") };
  } catch {
    const fallback = demo();
    fallback.mode = "demo";
    fallback.notice = "The live model failed, so this audit used the built-in demo findings instead.";
    return { ok: true, result: fallback };
  }
}

export async function handleAuditHttp(req: HttpRequest, res: HttpResponse, deps: AuditDeps = {}): Promise<void> {
  cors(res);
  if (methodOf(req) === "OPTIONS") {
    res.status(204).json(null);
    return;
  }
  if (methodOf(req) !== "POST") {
    res.status(405).json({ error: "Use POST." });
    return;
  }
  if (tooLarge(req)) {
    res.status(413).json({ error: "The request is too large." });
    return;
  }
  const body = readJsonBody(req);
  if (!body.ok) {
    res.status(400).json({ error: body.error });
    return;
  }
  const ip = clientIp(req.headers ?? {}, req.socket?.remoteAddress ?? "unknown");
  if (!allow(`audit:${ip}`, AUDIT_LIMIT, AUDIT_WINDOW_MS, deps.now ?? Date.now())) {
    res.status(429).json({ error: "Too many audits. Please wait a moment and try again." });
    return;
  }
  const result = await executeAudit(body.value, deps);
  if (!result.ok) {
    res.status(result.status).json({ error: result.error });
    return;
  }
  res.status(200).json(result.result);
}
