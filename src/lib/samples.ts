import type { Finding, SampleId } from "./schemas.js";

export interface CodeSample {
  id: SampleId;
  title: string;
  language: "javascript";
  filename: string;
  summary: string;
  code: string;
  findings: Finding[];
}

export const SAMPLES: CodeSample[] = [
  {
    id: "sql-injection",
    title: "SQL injection",
    language: "javascript",
    filename: "users-route.js",
    summary: "A query string is concatenated into SQL, so a crafted name can change the query.",
    code: `import express from "express";
import { db } from "./db.js";

const app = express();

app.get("/users", async (req, res) => {
  const name = req.query.name;
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  const rows = await db.query(sql);
  res.json(rows);
});

app.listen(3000);
`,
    findings: [
      {
        line: 8,
        severity: "critical",
        cwe: "CWE-89",
        title: "SQL built with string concatenation",
        explanation:
          "The name query parameter is inserted into the SQL string with no escaping or parameters, so an attacker can close the quote and change the query.",
        fix: "Use a parameterized query, for example db.query('SELECT * FROM users WHERE name = $1', [name]), and reject unexpected input early.",
      },
    ],
  },
  {
    id: "xss",
    title: "Cross-site scripting",
    language: "javascript",
    filename: "comments.js",
    summary: "Untrusted HTML is written into the page with innerHTML.",
    code: `function renderComment(comment) {
  const box = document.getElementById("comments");
  box.innerHTML += "<p>" + comment.author + ": " + comment.body + "</p>";
}

window.addEventListener("message", (event) => {
  document.getElementById("preview").innerHTML = event.data.html;
});
`,
    findings: [
      {
        line: 3,
        severity: "high",
        cwe: "CWE-79",
        title: "Untrusted comment rendered as HTML",
        explanation:
          "comment.author and comment.body are concatenated into innerHTML. A payload such as a script or event handler will run in the page.",
        fix: "Create elements with document.createElement and assign textContent, or use a trusted escaping helper. Never assign untrusted strings to innerHTML.",
      },
      {
        line: 7,
        severity: "high",
        cwe: "CWE-79",
        title: "postMessage HTML is inserted unsafely",
        explanation:
          "event.data.html is written to the DOM with no origin check and no sanitization, so any site that can message this window can inject script.",
        fix: "Check event.origin against an allow-list, treat the payload as text, and assign it with textContent rather than innerHTML.",
      },
    ],
  },
  {
    id: "hardcoded-secret",
    title: "Hardcoded secret",
    language: "javascript",
    filename: "billing.js",
    summary: "A placeholder API key and database password are embedded in source.",
    code: `const API_KEY = "sk-demo-not-a-real-secret-example-only";
const dbPassword = "ChangeMe123!";

export async function charge(customerId) {
  const res = await fetch("https://api.example.com/charge", {
    method: "POST",
    headers: { Authorization: \`Bearer \${API_KEY}\` },
    body: JSON.stringify({ customerId, dbPassword }),
  });
  return res.json();
}
`,
    findings: [
      {
        line: 1,
        severity: "critical",
        cwe: "CWE-798",
        title: "API key hardcoded in source",
        explanation:
          "The billing function ships a static API key in the file. Anyone with the source can reuse it, and rotating the key later means shipping a new build.",
        fix: "Load the secret from an environment variable or a secret manager at runtime, and keep a placeholder only in .env.example.",
      },
      {
        line: 2,
        severity: "high",
        cwe: "CWE-798",
        title: "Database password hardcoded in source",
        explanation:
          "dbPassword is a literal in the same file and is also sent to an external API in the request body.",
        fix: "Read the password from a secret store and do not send it to third-party APIs unless that API must have it.",
      },
    ],
  },
  {
    id: "path-traversal",
    title: "Path traversal",
    language: "javascript",
    filename: "files.js",
    summary: "A user-supplied file name is joined onto a directory with no extra checks.",
    code: `import fs from "node:fs/promises";
import path from "node:path";

const ROOT = "/var/data/files";

export async function readUserFile(fileName) {
  const fullPath = path.join(ROOT, fileName);
  return fs.readFile(fullPath, "utf8");
}
`,
    findings: [
      {
        line: 7,
        severity: "high",
        cwe: "CWE-22",
        title: "User path is joined without a root check",
        explanation:
          "path.join does not block segments such as ../, so fileName can escape ROOT and read other files on the server.",
        fix: "Resolve the path, then confirm it still starts with the resolved ROOT directory before calling readFile. Reject names that contain .. or absolute prefixes.",
      },
    ],
  },
];

export function getSample(id: SampleId): CodeSample {
  const sample = SAMPLES.find((item) => item.id === id);
  if (!sample) throw new Error(`Unknown sample: ${id}`);
  return sample;
}
