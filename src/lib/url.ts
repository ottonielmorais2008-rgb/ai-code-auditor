export const MAX_CODE_CHARS = 40_000;
export const MAX_CODE_BYTES = 64_000;
export const FETCH_TIMEOUT_MS = 8_000;

const BLOB = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/(?:blob|raw)\/(.+)$/i;
const RAW = /^https:\/\/raw\.githubusercontent\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/(.+)$/i;

export type ParsedGitHubFile = {
  owner: string;
  repo: string;
  rest: string;
  rawUrl: string;
  label: string;
};

function rejectName(name: string): boolean {
  const lower = name.toLowerCase();
  return !name || name === "." || name === ".." || lower === "github" || name.includes("\\");
}

function cleanPath(rest: string): string | null {
  const trimmed = rest.replace(/\/+$/, "").replace(/^\/+/, "");
  if (!trimmed) return null;
  const decoded = safeDecode(trimmed);
  if (!decoded) return null;
  const parts = decoded.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  if (parts.some((part) => part === "." || part === ".." || part.includes("\\"))) return null;
  return parts.map((part) => encodeURIComponent(part)).join("/");
}

function safeDecode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

export function parseGitHubFileUrl(input: string): { ok: true; file: ParsedGitHubFile } | { ok: false; error: string } {
  if (typeof input !== "string" || !input.trim()) {
    return { ok: false, error: "A public GitHub file URL is required." };
  }
  const rawInput = input.trim();
  if (rawInput.length > 500) {
    return { ok: false, error: "That URL is too long." };
  }
  let parsed: URL;
  try {
    parsed = new URL(rawInput);
  } catch {
    return { ok: false, error: "That is not a valid URL." };
  }
  if (parsed.protocol !== "https:") {
    return { ok: false, error: "Only https GitHub file URLs are allowed." };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: "URLs with credentials are not allowed." };
  }
  const href = `${parsed.origin}${parsed.pathname}`;
  const blob = href.match(BLOB);
  const raw = href.match(RAW);
  const match = blob ?? raw;
  if (!match) {
    return {
      ok: false,
      error: "Use a public github.com blob URL or a raw.githubusercontent.com file URL.",
    };
  }
  const owner = match[1]!;
  const repo = match[2]!;
  const rest = cleanPath(match[3]!);
  if (rejectName(owner) || rejectName(repo) || !rest) {
    return { ok: false, error: "That GitHub file path is not allowed." };
  }
  const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${rest}`;
  const label = `${owner}/${repo}/${safeDecode(rest)}`;
  return { ok: true, file: { owner, repo, rest, rawUrl, label } };
}

export async function fetchPublicGitHubFile(
  url: string,
  fetchFn: typeof fetch = fetch,
  timeoutMs = FETCH_TIMEOUT_MS,
): Promise<{ ok: true; code: string; label: string } | { ok: false; status: number; error: string }> {
  const parsed = parseGitHubFileUrl(url);
  if (!parsed.ok) return { ok: false, status: 400, error: parsed.error };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchFn(parsed.file.rawUrl, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: "text/plain, text/*, application/octet-stream",
        "User-Agent": "ai-code-auditor-demo",
      },
    });
    if (response.status >= 300 && response.status < 400) {
      return { ok: false, status: 400, error: "The file URL redirected; only direct public raw files are fetched." };
    }
    if (response.status === 404) {
      return { ok: false, status: 404, error: "That file was not found. It may be private or the path may be wrong." };
    }
    if (response.status === 401 || response.status === 403) {
      return { ok: false, status: 400, error: "That file is not publicly readable." };
    }
    if (!response.ok) {
      return { ok: false, status: 502, error: "The GitHub raw file could not be fetched right now." };
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.byteLength > MAX_CODE_BYTES) {
      return { ok: false, status: 413, error: "That file is larger than the 64 KB limit." };
    }
    if (buffer.includes(0)) {
      return { ok: false, status: 400, error: "That file looks binary, not source text." };
    }
    const code = buffer.toString("utf8");
    if (!code.trim()) {
      return { ok: false, status: 400, error: "That file is empty." };
    }
    if (code.length > MAX_CODE_CHARS) {
      return { ok: false, status: 413, error: "That file is larger than the 40,000 character limit." };
    }
    return { ok: true, code, label: parsed.file.label };
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return {
      ok: false,
      status: 502,
      error: aborted ? "Fetching the file timed out." : "The GitHub raw file could not be fetched right now.",
    };
  } finally {
    clearTimeout(timer);
  }
}
