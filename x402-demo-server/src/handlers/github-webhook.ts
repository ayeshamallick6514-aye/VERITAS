import { Context } from "hono";
import { createHmac, timingSafeEqual } from "crypto";
import { executeDeepXaiAnalysis } from "./audit-agent.js";

// ─── Types ────────────────────────────────────────────────────────────────────
interface GitHubPRPayload {
  action: string;
  number: number;
  pull_request: {
    title: string;
    head: { sha: string; ref: string };
    base: { ref: string };
    diff_url: string;
    comments_url: string;
    user: { login: string };
  };
  repository: {
    full_name: string;
    html_url: string;
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function verifySig(secret: string, body: string, sigHeader: string): boolean {
  try {
    const expected = "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
    const a = Buffer.from(expected);
    const b = Buffer.from(sigHeader);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function extractCodeFromDiff(diff: string): { code: string; language: "pyteal" | "solidity" | "teal" | "qds" } {
  // Pull only added lines from the diff (+lines)
  const addedLines = diff
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .map((l) => l.slice(1))
    .join("\n");

  const lower = addedLines.toLowerCase();
  let language: "pyteal" | "solidity" | "teal" | "qds" = "solidity";
  if (lower.includes("pyteal") || lower.includes("from pyteal")) language = "pyteal";
  else if (lower.includes(".teal") || lower.includes("#pragma version")) language = "teal";
  else if (lower.includes("ecdsa") || lower.includes("secp256k1") || lower.includes("ecrecover")) language = "qds";

  return { code: addedLines || diff, language };
}

function buildPRComment(report: ReturnType<typeof executeDeepXaiAnalysis>, prTitle: string, sha: string): string {
  const severityEmoji: Record<string, string> = {
    CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵", INFORMATIONAL: "⚪",
  };

  const header = [
    `## 🤖 AuditAgent-X Security Report`,
    `> **PR:** ${prTitle} | **Commit:** \`${sha.slice(0, 7)}\` | **Protocol:** x402-AVM (Headless Agent Mode)`,
    ``,
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Vulnerability Score | **${report.vulnerabilityScore} / 100** |`,
    `| Status | **${report.status}** |`,
    `| Total Issues | **${report.totalIssuesCount}** |`,
    `| AST Nodes | ${report.astMetrics.nodeCount} |`,
    `| Cyclomatic Complexity | ${report.astMetrics.cyclomaticComplexity} |`,
    `| Risk-Weighted Entropy | ${report.astMetrics.riskWeightedEntropy} |`,
    ``,
  ].join("\n");

  if (report.detailedFindings.length === 0) {
    return header + `### ✅ No critical vulnerabilities detected in this PR's changes.\n`;
  }

  const findings = report.detailedFindings.map((f) => [
    `### ${severityEmoji[f.severity] ?? "⚪"} \`${f.id}\` — ${f.title}`,
    `**Severity:** ${f.severity} | **Risk Weight:** ${f.riskWeight} | **${f.cwe}**`,
    ``,
    `${f.description}`,
    ``,
    `**Affected Lines:** ${f.affectedLines.join(", ")}`,
    ``,
    `<details>`,
    `<summary>📋 XAI Attributions</summary>`,
    ``,
    f.attributions.map((a) =>
      `- \`${a.token}\` — Line ${a.line} | Node: \`${a.astNodeType}\` | Weight: ${a.weight}`
    ).join("\n"),
    ``,
    `</details>`,
    ``,
    `<details>`,
    `<summary>🔧 Counterfactual Patch</summary>`,
    ``,
    "```diff",
    f.counterfactualFix.diff,
    "```",
    ``,
    `> ${f.counterfactualFix.explanation}`,
    ``,
    `</details>`,
    ``,
    `---`,
  ].join("\n")).join("\n");

  const footer = [
    ``,
    `<sub>🔐 Powered by **AuditAgent-X** | Algorand AVM x402 Protocol | [View Dashboard](http://localhost:5173)</sub>`,
  ].join("\n");

  return header + findings + footer;
}

async function postPRComment(commentsUrl: string, body: string, token: string): Promise<void> {
  const res = await fetch(commentsUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify({ body }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub API error ${res.status}: ${err}`);
  }
}

// ─── Handler ──────────────────────────────────────────────────────────────────
export async function handleGithubWebhook(c: Context) {
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN ?? "";
  const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET ?? "";
  const isDryRun = !GITHUB_TOKEN;

  // 1. Verify signature
  const rawBody = await c.req.text();
  const sigHeader = c.req.header("x-hub-signature-256") ?? "";

  if (WEBHOOK_SECRET && !verifySig(WEBHOOK_SECRET, rawBody, sigHeader)) {
    console.warn("[AuditAgent-X GitHub Bot] HMAC signature mismatch — rejected.");
    return c.json({ error: "Invalid webhook signature" }, 401);
  }

  // 2. Parse and gate on PR events
  let payload: GitHubPRPayload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return c.json({ error: "Invalid JSON payload" }, 400);
  }

  const event = c.req.header("x-github-event");
  if (event !== "pull_request") {
    return c.json({ skipped: true, reason: `Event '${event}' not handled` }, 200);
  }

  if (!(payload.action === "opened" || payload.action === "synchronize")) {
    return c.json({ skipped: true, reason: `Action '${payload.action}' not handled` }, 200);
  }

  const pr = payload.pull_request;
  const repoName = payload.repository.full_name;
  console.log(`[AuditAgent-X GitHub Bot] PR #${payload.number} — ${pr.title} (${repoName})`);

  // 3. Fetch PR diff
  let diff = "";
  try {
    const diffRes = await fetch(pr.diff_url, {
      headers: GITHUB_TOKEN ? { Authorization: `Bearer ${GITHUB_TOKEN}` } : {},
    });
    if (diffRes.ok) diff = await diffRes.text();
  } catch (e) {
    console.warn("[AuditAgent-X GitHub Bot] Could not fetch diff:", e);
  }

  // 4. Extract code & run analysis
  const { code, language } = extractCodeFromDiff(diff);
  const report = executeDeepXaiAnalysis({ code, language });

  console.log(
    `[AuditAgent-X GitHub Bot] Analysis complete — Score: ${report.vulnerabilityScore}, ` +
    `Issues: ${report.totalIssuesCount}, Findings: ${report.detailedFindings.length}`
  );

  // 5. Build comment
  const comment = buildPRComment(report, pr.title, pr.head.sha);

  // 6. Post or dry-run
  if (isDryRun) {
    console.log("[AuditAgent-X GitHub Bot] DRY RUN — No GITHUB_TOKEN set. Comment preview:");
    console.log(comment);
    return c.json({
      dryRun: true,
      message: "Set GITHUB_TOKEN env var to enable live PR commenting.",
      report,
      commentPreview: comment,
    }, 200);
  }

  try {
    await postPRComment(pr.comments_url, comment, GITHUB_TOKEN);
    console.log(`[AuditAgent-X GitHub Bot] Comment posted to PR #${payload.number}.`);
    return c.json({ success: true, prNumber: payload.number, findings: report.detailedFindings.length }, 200);
  } catch (e: any) {
    console.error("[AuditAgent-X GitHub Bot] Failed to post comment:", e.message);
    return c.json({ error: e.message }, 500);
  }
}
