import { z } from "zod";

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export const LANGUAGES = ["javascript", "typescript", "python", "go", "java", "php", "ruby", "other"] as const;
export const LanguageSchema = z.enum(LANGUAGES);
export type Language = z.infer<typeof LanguageSchema>;

export const SOURCE_KINDS = ["paste", "url", "sample"] as const;
export const SourceKindSchema = z.enum(SOURCE_KINDS);
export type SourceKind = z.infer<typeof SourceKindSchema>;

export const RUN_MODES = ["live", "demo", "sample"] as const;
export const RunModeSchema = z.enum(RUN_MODES);
export type RunMode = z.infer<typeof RunModeSchema>;

export const SAMPLE_IDS = ["sql-injection", "xss", "hardcoded-secret", "path-traversal"] as const;
export const SampleIdSchema = z.enum(SAMPLE_IDS);
export type SampleId = z.infer<typeof SampleIdSchema>;

export const CweSchema = z
  .string()
  .trim()
  .regex(/^CWE-\d{1,4}$/i, "CWE id must look like CWE-89.")
  .transform((value) => value.toUpperCase());

export const FindingSchema = z.object({
  line: z.number().int().min(1).max(20_000),
  severity: SeveritySchema,
  cwe: CweSchema,
  title: z.string().trim().min(3).max(80),
  explanation: z.string().trim().min(10).max(600),
  fix: z.string().trim().min(10).max(800),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ModelAuditSchema = z.object({
  summary: z.string().trim().min(1).max(400),
  findings: z.array(FindingSchema).max(30),
});
export type ModelAudit = z.infer<typeof ModelAuditSchema>;

export const AuditResultSchema = ModelAuditSchema.extend({
  mode: RunModeSchema,
  language: LanguageSchema.optional(),
  source: SourceKindSchema,
  sourceLabel: z.string().trim().min(1).max(200).optional(),
  notice: z.string().trim().max(400).optional(),
  code: z.string().max(40_000).optional(),
});
export type AuditResult = z.infer<typeof AuditResultSchema>;

export const AuditInputSchema = z
  .object({
    code: z.string().max(40_000).optional(),
    url: z.string().trim().max(500).optional(),
    language: LanguageSchema.optional(),
    mode: z.enum(["live", "demo"]).optional(),
    sampleId: SampleIdSchema.optional(),
  })
  .strict();
export type AuditInput = z.infer<typeof AuditInputSchema>;

export function parseAuditInput(input: unknown): { ok: true; value: AuditInput } | { ok: false; error: string } {
  const parsed = AuditInputSchema.safeParse(input);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    return { ok: false, error: first?.message ?? "A valid audit request is required." };
  }
  const value = parsed.data;
  const hasCode = Boolean(value.code && value.code.trim());
  if (!hasCode && !value.url && !value.sampleId) {
    return { ok: false, error: "Paste some source, provide a public GitHub file URL, or choose a sample." };
  }
  return { ok: true, value };
}

export function formatZodError(error: z.ZodError): string {
  const first = error.issues[0];
  if (!first) return "The payload failed schema validation.";
  const path = first.path.length ? first.path.join(".") : "payload";
  return `${path}: ${first.message}`;
}
