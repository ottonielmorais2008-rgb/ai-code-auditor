import { describe, expect, it } from "vitest";
import { demoFindingsFor, detectSample, scanForDemoFindings } from "../src/lib/demo.js";
import { SAMPLES } from "../src/lib/samples.js";
import { finalizeAudit } from "../src/lib/auditor.js";

describe("sample library", () => {
  it("has canned findings that point at real lines in each snippet", () => {
    expect(SAMPLES).toHaveLength(4);
    for (const sample of SAMPLES) {
      const lines = sample.code.replace(/\n$/, "").split("\n").length;
      expect(sample.findings.length).toBeGreaterThan(0);
      for (const finding of sample.findings) {
        expect(finding.line).toBeGreaterThanOrEqual(1);
        expect(finding.line).toBeLessThanOrEqual(lines);
        expect(finding.cwe).toMatch(/^CWE-\d+$/);
      }
    }
  });

  it("returns the canned SQL injection result for that sample", () => {
    const sql = SAMPLES.find((sample) => sample.id === "sql-injection")!;
    expect(detectSample(sql.code)).toBe("sql-injection");
    const result = demoFindingsFor(sql.code);
    expect(result.findings[0]?.cwe).toBe("CWE-89");
    expect(finalizeAudit(result, sql.code).findings[0]?.line).toBe(8);
  });
});

describe("demo heuristic", () => {
  it("flags SQL, XSS, secrets and path joins in unknown snippets", () => {
    const code = [
      'const q = "SELECT * FROM users WHERE id = \'" + userId + "\'";',
      'box.innerHTML = input;',
      'const API_KEY = "sk-demo-not-a-real-secret-example-only";',
      'const fullPath = path.join(ROOT, req.query.file);',
    ].join("\n");
    const result = scanForDemoFindings(code);
    const cwes = result.findings.map((finding) => finding.cwe).sort();
    expect(cwes).toEqual(["CWE-22", "CWE-79", "CWE-798", "CWE-89"]);
  });

  it("returns no findings for a clean snippet", () => {
    const result = scanForDemoFindings("export const add = (a, b) => a + b;\n");
    expect(result.findings).toEqual([]);
    expect(result.summary).toMatch(/no obvious/i);
  });
});
