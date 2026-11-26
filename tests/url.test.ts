import { describe, expect, it, vi } from "vitest";
import { fetchPublicGitHubFile, parseGitHubFileUrl } from "../src/lib/url.js";

describe("parseGitHubFileUrl", () => {
  it("converts a public blob URL into a raw.githubusercontent.com URL", () => {
    const parsed = parseGitHubFileUrl("https://github.com/acme/app/blob/main/src/app.js");
    expect(parsed).toMatchObject({
      ok: true,
      file: {
        rawUrl: "https://raw.githubusercontent.com/acme/app/main/src/app.js",
        label: "acme/app/main/src/app.js",
      },
    });
  });

  it("accepts an already-raw URL and strips a trailing slash or query", () => {
    const parsed = parseGitHubFileUrl("https://raw.githubusercontent.com/acme/app/main/src/app.js?token=no#L1");
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.file.rawUrl).toBe("https://raw.githubusercontent.com/acme/app/main/src/app.js");
    }
  });

  it("rejects credentials, http, non-GitHub hosts and path traversal", () => {
    expect(parseGitHubFileUrl("http://github.com/acme/app/blob/main/a.js").ok).toBe(false);
    expect(parseGitHubFileUrl("https://user:pass@github.com/acme/app/blob/main/a.js").ok).toBe(false);
    expect(parseGitHubFileUrl("https://evil.example/raw/acme/app/main/a.js").ok).toBe(false);
    expect(parseGitHubFileUrl("https://github.com/acme/app/blob/main/../secret.js").ok).toBe(false);
    expect(parseGitHubFileUrl("https://github.com/acme/app/issues/1").ok).toBe(false);
  });
});

describe("fetchPublicGitHubFile", () => {
  it("returns the file text from a public raw URL", async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => new Response("const ok = true;\n", { status: 200 }));
    const result = await fetchPublicGitHubFile("https://github.com/acme/app/blob/main/src/app.js", fetchFn);
    expect(result).toMatchObject({ ok: true, code: "const ok = true;\n", label: "acme/app/main/src/app.js" });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(String(fetchFn.mock.calls[0]?.[0])).toBe("https://raw.githubusercontent.com/acme/app/main/src/app.js");
  });

  it("rejects private, missing, redirected or binary files", async () => {
    const missing = await fetchPublicGitHubFile("https://github.com/acme/app/blob/main/gone.js", async () => new Response("", { status: 404 }));
    expect(missing).toMatchObject({ ok: false, status: 404 });

    const denied = await fetchPublicGitHubFile("https://github.com/acme/app/blob/main/secret.js", async () => new Response("", { status: 403 }));
    expect(denied).toMatchObject({ ok: false, status: 400 });

    const redirected = await fetchPublicGitHubFile(
      "https://github.com/acme/app/blob/main/a.js",
      async () => new Response("", { status: 302, headers: { Location: "https://evil.example/a.js" } }),
    );
    expect(redirected).toMatchObject({ ok: false, status: 400 });

    const binary = await fetchPublicGitHubFile(
      "https://github.com/acme/app/blob/main/a.bin",
      async () => new Response(Buffer.from([0, 1, 2, 3]), { status: 200 }),
    );
    expect(binary.ok).toBe(false);
  });
});
