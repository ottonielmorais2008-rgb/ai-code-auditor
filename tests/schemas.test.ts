import { describe, expect, it } from "vitest";
import { FindingSchema, formatZodError, parseAuditInput } from "../src/lib/schemas.js";

const validFinding = {
  line: 3,
  severity: "high",
  cwe: "CWE-89",
  title: "SQL injection",
  explanation: "The query is built with string concatenation.",
  fix: "Use a parameterized query instead of concatenation.",
};

describe("finding schema", () => {
  it("accepts a complete finding and normalizes the CWE id", () => {
    expect(FindingSchema.parse({ ...validFinding, cwe: "cwe-89" }).cwe).toBe("CWE-89");
  });

  it("rejects a missing title, a bad CWE and a zero line", () => {
    expect(FindingSchema.safeParse({ ...validFinding, title: "ab" }).success).toBe(false);
    expect(FindingSchema.safeParse({ ...validFinding, cwe: "89" }).success).toBe(false);
    expect(FindingSchema.safeParse({ ...validFinding, line: 0 }).success).toBe(false);
    expect(formatZodError(FindingSchema.safeParse({ ...validFinding, cwe: "89" }).error!)).toMatch(/CWE/i);
  });
});

describe("parseAuditInput", () => {
  it("accepts pasted code, a URL or a sample id", () => {
    expect(parseAuditInput({ code: "const x = 1" }).ok).toBe(true);
    expect(parseAuditInput({ url: "https://github.com/owner/repo/blob/main/a.js" }).ok).toBe(true);
    expect(parseAuditInput({ sampleId: "xss" }).ok).toBe(true);
  });

  it("rejects an empty body, an unknown sample and oversized code", () => {
    expect(parseAuditInput({}).ok).toBe(false);
    expect(parseAuditInput({ sampleId: "buffer-overflow" }).ok).toBe(false);
    expect(parseAuditInput({ code: "x".repeat(40_001) }).ok).toBe(false);
  });
});
