# AI Code Auditor

**Live demo:** https://ai-code-auditor-two.vercel.app

Paste source or a public GitHub file URL. The auditor returns structured findings, each with a line number, severity, CWE id, a short explanation and a suggested fix. The model output is validated with Zod; a malformed reply is retried once.

The page opens on an intentionally vulnerable SQL-injection sample so you can see highlighted lines and findings without calling a model.

## How it works

1. **Input** — paste a snippet, load one of the built-in samples (SQL injection, XSS, a hardcoded secret placeholder, or path traversal), or provide a public `github.com` blob / `raw.githubusercontent.com` file URL.
2. **Audit** — `POST /api/audit` sends the source to Gemini (`gemini-3.5-flash-lite`) from a Vercel serverless function. The API key lives only in Vercel environment variables and is never sent to the browser. Requests are rate-limited and size-capped.
3. **Result** — findings are validated, sorted by severity, and shown next to the source with the matching lines highlighted.

If the key is missing or the model fails, the same UI uses deterministic demo findings: canned results for the samples, and a small local heuristic for other snippets. "Use demo findings" always takes that path and does not call the model.

## Tech

- React 19, TypeScript, Vite
- Zod schemas for each finding and the audit result
- Vercel serverless function for the optional Gemini path
- Vitest unit tests for the schemas, URL checks, demo fallback, auditor parsing and the API handler (with a mocked model)
- GitHub Actions: lint, typecheck, test and build on every push and pull request

```
src/lib/schemas.ts   Zod contracts for findings and the audit result
src/lib/url.ts       Public GitHub URL validation and raw-file fetch
src/lib/auditor.ts   Parse, retry once, clamp lines and sort by severity
src/lib/demo.ts      Sample results and the deterministic heuristic
src/lib/api.ts       /api/audit handler, rate limit and live-to-demo fallback
```

## Limits

- Only public GitHub file URLs are fetched, and only from `raw.githubusercontent.com`. Private files, redirects, binary files and branches with slashes in the name (use the raw URL in that case) are rejected or may fail.
- Source is capped at 40,000 characters (64 KB for fetched files).
- The model is asked to report issues in the provided snippet only; it can miss bugs or flag a false positive.
- Malformed model output is retried once; a second failure falls back to demo findings.
- The demo heuristic is a small pattern matcher, not a complete static analyzer.
- This is an educational demo, not a substitute for a security review or a production SAST tool.

## Running it yourself

Requires Node.js 20.9+.

```bash
npm install
npm test
npm run dev
```

The Vite dev server also serves `/api/audit`. To try the live model locally, copy `.env.example` to `.env` and set `GEMINI_API_KEY`. The samples and demo mode work without it.

## License

[MIT](LICENSE)
