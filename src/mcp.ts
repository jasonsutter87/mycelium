// MCP server (stdio). Lets Claude Code act as the "fix agent": find what's vulnerable,
// explain it, plan the upgrade, apply it on a branch, verify, and hand back a diff to review.
//
//   claude mcp add mycelium -- /path/to/Mycelium/bin/mycelium mcp
//
// Nothing here may write to stdout except the MCP transport.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolve } from "node:path";
import { openDb } from "./db.ts";
import { scanRoots } from "./scan.ts";
import { checkAll, severityRank } from "./osv.ts";
import { findings, impact, whyPaths } from "./graph.ts";
import { applyFixes, planFixes } from "./fix.ts";
import { audit } from "./audit.ts";
import { enrich } from "./depsdev.ts";

const db = openDb();
const server = new McpServer({ name: "mycelium", version: "0.2.0" });

const json = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data, null, 1) }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: "text" as const, text: (e as Error).message }] });
const roots = (): string[] =>
  JSON.parse((db.prepare("SELECT value FROM settings WHERE key = 'roots'").get() as { value: string } | undefined)?.value ?? "[]");

server.registerTool("mycelium_scan", {
  title: "Scan projects",
  description: "Map every project under the given folders (or the remembered ones): dependencies, transitive edges, hosts, domains, CI, images. Run before anything else if the graph may be stale.",
  inputSchema: { paths: z.array(z.string()).optional().describe("Folders to scan. Omit to rescan the remembered roots.") },
}, async ({ paths }) => {
  try {
    const list = paths?.length ? paths.map((p) => resolve(p)) : roots();
    if (!list.length) return fail(new Error("No folders known yet: pass paths."));
    db.prepare("INSERT INTO settings (key, value) VALUES ('roots', ?) ON CONFLICT DO UPDATE SET value = excluded.value").run(JSON.stringify(list));
    const s = scanRoots(db, list);
    return json({ projects: s.length, packages: s.reduce((n, p) => n + p.packages, 0), list: s.map(({ warnings, ...p }) => p) });
  } catch (e) {
    return fail(e);
  }
});

server.registerTool("mycelium_check", {
  title: "Check for vulnerabilities",
  description: "Query OSV.dev for every package in the graph. Returns findings that are new since the last check, plus totals.",
  inputSchema: {},
}, async () => {
  try {
    const fresh = await checkAll(db);
    const all = findings(db);
    const freshKeys = new Set(fresh.map((f) => `${f.packageId}|${f.vulnId}`));
    const newOnes = all.filter((f) => freshKeys.has(`${f.packageId}|${f.vulnId}`));
    return json({
      new: newOnes.slice(0, 50).map(brief),
      totals: countBy(all.map((f) => f.severity)),
      projectsAffected: new Set(all.flatMap((f) => f.hits.map((h) => h.project))).size,
    });
  } catch (e) {
    return fail(e);
  }
});

server.registerTool("mycelium_projects", {
  title: "List projects",
  description: "Every scanned project with its exposure (public-web / distributed / self-hosted / local), package count and open vulnerability counts by severity.",
  inputSchema: {},
}, async () => {
  const list = findings(db);
  const rows = db.prepare(`SELECT pr.name, pr.path, pr.exposure,
      (SELECT count(DISTINCT u.package_id) FROM uses u JOIN components c ON c.id = u.component_id WHERE c.project_id = pr.id) AS packages
    FROM projects pr ORDER BY pr.name`).all() as any[];
  return json(rows.map((r) => ({
    ...r,
    vulns: countBy(list.filter((f) => f.hits.some((h) => h.projectPath === r.path)).map((f) => f.severity)),
  })));
});

server.registerTool("mycelium_findings", {
  title: "Vulnerability findings",
  description: "Open vulnerabilities ranked by blast radius (severity × exposure × projects affected), with dependency paths and fixed versions.",
  inputSchema: {
    project: z.string().optional().describe("Limit to one project (name)."),
    min_severity: z.enum(["LOW", "MODERATE", "HIGH", "CRITICAL"]).optional(),
    include_dev: z.boolean().optional().describe("Include dev-only dependencies (default false)."),
    limit: z.number().int().positive().max(200).optional(),
  },
}, async ({ project, min_severity, include_dev, limit }) => {
  let list = findings(db, { includeDev: include_dev });
  if (project) list = list.filter((f) => f.hits.some((h) => h.project === project)).map((f) => ({ ...f, hits: f.hits.filter((h) => h.project === project) }));
  if (min_severity) list = list.filter((f) => severityRank(f.severity) >= severityRank(min_severity));
  return json({
    total: list.length,
    findings: list.slice(0, limit ?? 25).map((f) => ({
      ...brief(f),
      where: [...new Map(f.hits.map((h) => [h.project + h.component, h])).values()].map((h) => ({
        project: h.project, exposure: h.exposure, lockfile: h.component, direct: h.direct,
        path: h.direct ? undefined : whyPaths(db, h.componentId, f.packageId, 1)[0],
      })),
    })),
  });
});

server.registerTool("mycelium_impact", {
  title: "Which projects use a package",
  description: "Answer 'a CVE just dropped for X: am I affected?'. Lists every project using the package, versions, direct or transitive.",
  inputSchema: { package: z.string(), version: z.string().optional() },
}, async ({ package: name, version }) => {
  return json(impact(db, name, version).map(({ component_id, package_id, ...r }) => ({ ...r, direct: !!r.direct })));
});

server.registerTool("mycelium_why", {
  title: "Why is this package here",
  description: "Dependency chains showing how a package ends up in each project, e.g. next → postcss → nanoid.",
  inputSchema: { package: z.string(), version: z.string().optional(), project: z.string().optional() },
}, async ({ package: name, version, project }) => {
  const rows = impact(db, name, version).filter((r) => !project || r.project === project);
  return json(rows.map((r) => ({
    project: r.project, lockfile: r.component, version: r.version, direct: !!r.direct,
    paths: r.direct ? [] : whyPaths(db, r.component_id, r.package_id, 3),
  })));
});

server.registerTool("mycelium_fix_plan", {
  title: "Plan fixes for a project",
  description:
    "Read-only. For one project, groups vulnerabilities by package and proposes the upgrade: strategy (bump-direct, override, cargo-update, dotnet-add, pip-pin, uv-upgrade, go-get, gradle-edit, manual), target version, and whether it's a major (possibly breaking) bump. Review this before mycelium_fix_apply.",
  inputSchema: {
    project: z.string(),
    min_severity: z.enum(["LOW", "MODERATE", "HIGH", "CRITICAL"]).optional(),
    include_dev: z.boolean().optional(),
  },
}, async ({ project, min_severity, include_dev }) => {
  try {
    const plan = planFixes(db, project, { minSeverity: min_severity, includeDev: include_dev });
    return json({
      ...plan,
      summary: {
        automatic: plan.fixes.filter((f) => f.strategy !== "manual" && !f.breaking).length,
        major: plan.fixes.filter((f) => f.strategy !== "manual" && f.breaking).length,
        manual: plan.fixes.filter((f) => f.strategy === "manual").length,
      },
    });
  } catch (e) {
    return fail(e);
  }
});

server.registerTool("mycelium_fix_apply", {
  title: "Apply fixes to a project",
  description:
    "Applies the fix plan in a throwaway git worktree and commits it to a NEW branch mycelium/fix-<time> (the user's working folder and uncommitted work are never touched). Runs the package manager, re-reads lockfiles to confirm which vulnerabilities are actually gone, optionally runs build/test, optionally pushes and opens a PR. Major bumps are skipped unless allow_major. To fix build breaks afterwards: `git worktree add <dir> <branch>`, fix, commit, push.",
  inputSchema: {
    project: z.string(),
    min_severity: z.enum(["LOW", "MODERATE", "HIGH", "CRITICAL"]).optional(),
    only: z.array(z.string()).optional().describe("Only these package names."),
    allow_major: z.boolean().optional(),
    verify: z.boolean().optional().describe("Run build/test scripts afterwards."),
    pr: z.boolean().optional().describe("Commit, push the branch and open a GitHub PR into the branch the repo was on. Only when the user asked for a PR. Never merges."),
    dry_run: z.boolean().optional(),
    include_dev: z.boolean().optional(),
  },
  annotations: { destructiveHint: false, readOnlyHint: false, idempotentHint: false },
}, async (a) => {
  try {
    const plan = planFixes(db, a.project, { minSeverity: a.min_severity, includeDev: a.include_dev });
    const r = applyFixes(db, plan, { only: a.only, allowMajor: a.allow_major, verify: a.verify, dryRun: a.dry_run, pr: a.pr });
    if (r.applied.length && !a.dry_run) await checkAll(db);
    return json({
      branch: r.branch, repos: r.repos, committed: r.committed, prs: r.prs, fixed: r.fixed, stillVulnerable: r.stillVulnerable,
      failed: r.failed.map((f) => ({ package: f.fix.name, error: f.error })),
      skipped: r.skipped.map((s) => ({ package: s.fix.name, reason: s.reason })),
      verify: r.verify, log: r.log,
    });
  } catch (e) {
    return fail(e);
  }
});

server.registerTool("mycelium_audit", {
  title: "Supply-chain audit (non-CVE risk)",
  description:
    "Everything that isn't a known CVE: malicious packages (OpenSSF MAL feed) and install scripts, untrusted package sources / dependency confusion, license risk (AGPL/GPL/non-commercial vs. how the project ships), deprecated, outdated (2+ majors), abandoned (no release in 2 years), container/compose/GitHub Actions misconfig, and committed .env files.",
  inputSchema: {
    project: z.string().optional(),
    category: z.enum(["malicious", "source", "license", "deprecated", "outdated", "abandoned", "infra"]).optional(),
    min_severity: z.enum(["LOW", "MODERATE", "HIGH", "CRITICAL"]).optional(),
    refresh: z.boolean().optional().describe("Fetch fresh registry metadata from deps.dev first (default true)."),
  },
}, async ({ project, category, min_severity, refresh }) => {
  try {
    if (refresh !== false) await enrich(db);
    let list = audit(db, { project, category });
    if (min_severity) list = list.filter((i) => severityRank(i.severity) >= severityRank(min_severity));
    return json({ total: list.length, issues: list.slice(0, 100).map(({ projectPath, ...i }) => i) });
  } catch (e) {
    return fail(e);
  }
});

function brief(f: ReturnType<typeof findings>[number]) {
  return {
    severity: f.severity, risk: f.risk, package: `${f.name}@${f.version}`, ecosystem: f.ecosystem, fixed: f.fixed,
    advisory: f.cve ?? f.vulnId, summary: f.summary, url: f.url, projects: [...new Set(f.hits.map((h) => h.project))],
  };
}
function countBy(xs: string[]) {
  const o: Record<string, number> = {};
  for (const x of xs) o[x] = (o[x] ?? 0) + 1;
  return o;
}

await server.connect(new StdioServerTransport());
