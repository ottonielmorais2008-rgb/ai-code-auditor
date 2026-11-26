import { describe, expect, it } from "vitest";
import { clampFindings, completeJsonAudit, parseModelAudit, sortFindings } from "../src/lib/auditor.js";
import { queueClient } from "./helpers.js";
import type { Finding } from "../src/lib/schemas.js";

const finding = (overrides: Partial<Finding>): Finding => ({
  line: 1,
  severity: "low",
  cwe: "CWE-22",
  title: "Path issue",
  explanation: "The path is built from user input.",
  fix: "Resolve the path and keep it inside the root.",
  ...overrides,
});

describe("sort and clamp findings", () => {
  it("sorts by severity and then by line", () => {
    const sorted = sortFindings([
      finding({ line: 8, severity: "high", title: "Second high" }),
      finding({ line: 2, severity: "low", title: "Low" }),
      finding({ line: 4, severity: "high", title: "First high" }),
      finding({ line: 1, severity: "critical", title: "Critical" }),
    ]);
    expect(sorted.map((item) => item.title)).toEqual(["Critical", "First high", "Second high", "Low"]);
  });

  it("clamps line numbers to the snippet length", () => {
    const clamped = clampFindings([finding({ line: 99 }), finding({ line: 1 })], "a\nb\nc");
    expect(clamped.map((item) => item.line)).toEqual([3, 1]);
  });
});

describe("parseModelAudit", () => {
  it("parses fenced JSON and rejects a malformed payload", () => {
    const text = "```json\n{\"summary\":\"Looks risky.\",\"findings\":[{\"line\":1,\"severity\":\"high\",\"cwe\":\"CWE-79\",\"title\":\"XSS\",\"explanation\":\"innerHTML is used with user data.\",\"fix\":\"Use textContent instead.\"}]}\n```";
    const parsed = parseModelAudit(text);
    expect(parsed.findings[0]?.cwe).toBe("CWE-79");
    expect(() => parseModelAudit("not json")).toThrow();
    expect(() => parseModelAudit('{"summary":"x","findings":[{"line":1}]}')).toThrow();
  });
});

describe("completeJsonAudit", () => {
  it("retries once when the first reply is malformed", async () => {
    const good = JSON.stringify({
      summary: "One issue.",
      findings: [
        {
          line: 1,
          severity: "high",
          cwe: "CWE-79",
          title: "XSS",
          explanation: "innerHTML is used with user data.",
          fix: "Use textContent instead.",
        },
      ],
    });
    const audit = await completeJsonAudit(queueClient(["nope", good]), {
      system: "sys",
      retrySystem: "retry",
      user: "code",
    });
    expect(audit.findings).toHaveLength(1);
  });

  it("fails when both replies are malformed", async () => {
    await expect(
      completeJsonAudit(queueClient(["nope", "still nope"]), { system: "sys", retrySystem: "retry", user: "code" }),
    ).rejects.toThrow();
  });
});
