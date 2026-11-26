import { beforeEach, describe, expect, it } from "vitest";
import { AUDIT_LIMIT, executeAudit, handleAuditHttp, resolveMode } from "../src/lib/api.js";
import { resetRateLimit } from "../src/lib/rate-limit.js";
import { SAMPLES } from "../src/lib/samples.js";
import { FakeResponse, jsonAudit, post, queueClient } from "./helpers.js";

beforeEach(() => {
  resetRateLimit();
});

describe("resolveMode", () => {
  it("uses demo findings when demo is requested or when no key is present", () => {
    expect(resolveMode("demo", true)).toMatchObject({ mode: "demo", useMock: true });
    expect(resolveMode("live", false)).toMatchObject({ mode: "demo", useMock: true });
    expect(resolveMode("live", true)).toEqual({ mode: "live", useMock: false });
  });
});

describe("executeAudit", () => {
  it("rejects an empty request", async () => {
    const result = await executeAudit({});
    expect(result).toMatchObject({ ok: false, status: 400 });
  });

  it("returns canned demo findings when no key is configured", async () => {
    const sample = SAMPLES[0]!;
    const result = await executeAudit({ sampleId: sample.id }, { env: {} });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.result.mode).toBe("demo");
      expect(result.result.findings[0]?.cwe).toBe("CWE-89");
      expect(result.result.notice).toMatch(/no api key/i);
      expect(result.result.code).toBe(sample.code);
    }
  });

  it("uses a live mocked model and sorts findings by severity", async () => {
    const payload = jsonAudit({
      findings: [
        {
          line: 3,
          severity: "low",
          cwe: "CWE-116",
          title: "Encoding",
          explanation: "Output encoding is incomplete on this line.",
          fix: "Encode the output for the destination context.",
        },
        {
          line: 1,
          severity: "critical",
          cwe: "CWE-89",
          title: "SQL injection",
          explanation: "The query is concatenated with a request value.",
          fix: "Use a parameterized query.",
        },
      ],
    });
    const result = await executeAudit(
      { code: "a\nb\nc", mode: "live" },
      { env: { GEMINI_API_KEY: "test-key" }, client: queueClient([payload]) },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.result.mode).toBe("live");
      expect(result.result.findings.map((finding) => finding.severity)).toEqual(["critical", "low"]);
      expect(result.result.notice).toBeUndefined();
    }
  });

  it("retries a malformed model reply, then falls back to demo if both fail", async () => {
    const recovered = await executeAudit(
      { code: 'box.innerHTML = input;', mode: "live" },
      { env: { GEMINI_API_KEY: "test-key" }, client: queueClient(["nope", jsonAudit()]) },
    );
    expect(recovered.ok).toBe(true);
    if (recovered.ok) expect(recovered.result.mode).toBe("live");

    const fallback = await executeAudit(
      { code: 'box.innerHTML = input;', mode: "live" },
      { env: { GEMINI_API_KEY: "test-key" }, client: queueClient([new Error("down")]) },
    );
    expect(fallback.ok).toBe(true);
    if (fallback.ok) {
      expect(fallback.result.mode).toBe("demo");
      expect(fallback.result.notice).toMatch(/live model failed/i);
      expect(fallback.result.findings[0]?.cwe).toBe("CWE-79");
    }
  });

  it("fetches a public GitHub file through the provided fetch function", async () => {
    const fetchFn = (async (input: RequestInfo | URL) => {
      const url = String(input);
      expect(url).toBe("https://raw.githubusercontent.com/acme/app/main/src/app.js");
      return new Response('box.innerHTML = input;\n', { status: 200 });
    }) as typeof fetch;
    const result = await executeAudit(
      { url: "https://github.com/acme/app/blob/main/src/app.js", mode: "demo" },
      { env: {}, fetchFn },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.result.source).toBe("url");
      expect(result.result.sourceLabel).toBe("acme/app/main/src/app.js");
      expect(result.result.findings[0]?.cwe).toBe("CWE-79");
    }
  });
});

describe("handleAuditHttp", () => {
  it("answers OPTIONS and rejects methods other than POST", async () => {
    const options = new FakeResponse();
    await handleAuditHttp({ method: "OPTIONS" }, options);
    expect(options.statusCode).toBe(204);
    const wrong = new FakeResponse();
    await handleAuditHttp({ method: "GET" }, wrong);
    expect(wrong.statusCode).toBe(405);
  });

  it("rejects invalid JSON, oversized bodies and too many audits", async () => {
    const invalid = new FakeResponse();
    await handleAuditHttp(post("{"), invalid);
    expect(invalid.statusCode).toBe(400);

    const huge = new FakeResponse();
    await handleAuditHttp(post("x", { body: "n".repeat(80_001), headers: { "content-length": "80001" } }), huge);
    expect(huge.statusCode).toBe(413);

    for (let i = 0; i < AUDIT_LIMIT; i += 1) {
      const ok = new FakeResponse();
      await handleAuditHttp(post({ sampleId: "xss", mode: "demo" }), ok);
      expect(ok.statusCode).toBe(200);
    }
    const limited = new FakeResponse();
    await handleAuditHttp(post({ sampleId: "xss", mode: "demo" }), limited);
    expect(limited.statusCode).toBe(429);
  });
});
