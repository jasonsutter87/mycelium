// What the dashboard shows, as plain data: no HTML here, so it can be tested and later served from anywhere.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { audit, CATEGORY_LABEL } from "./audit.ts";
import { acceptanceCovers, acceptedCount, findings, loadAcceptances, type Finding } from "./graph.ts";
import { findDowngrade } from "./downgrade.ts";
import { planFixes } from "./fix.ts";
import { projectPrs } from "./prs.ts";

export type Severity = "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "UNKNOWN";
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"];

export interface ProjectRow {
  name: string;
  path: string;
  exposure: string;
  packages: number;
  open: number;
  bySeverity: Record<Severity, number>;
  accepted: number;
  status: "attention" | "clean" | "accepted";
  auditIssues: number;
  hosts: string[];
  scannedAt: string | null;
  prs: { number: number; url: string; state: string; needsPull: boolean; ready: boolean; reason?: string }[];
}

const key = (f: Finding) => `${f.ecosystem}|${f.name}@${f.version}|${f.vulnId}`;

/** A project's status: anything open needs attention; otherwise accepted items keep it from reading as fully clean. */
export function statusOf(open: number, accepted: number): ProjectRow["status"] {
  return open ? "attention" : accepted ? "accepted" : "clean";
}

// PR status shells out to git several times per project (seconds across an account) and rarely changes.
const PR_TTL_MS = 120_000;
let prCache = new Map<string, { at: number; value: ProjectRow["prs"] }>();
export const clearPrCache = () => {
  prCache = new Map();
  overviewCache = null;
};
function prsOf(db: DatabaseSync, path: string): ProjectRow["prs"] {
  const hit = prCache.get(path);
  if (hit && Date.now() - hit.at < PR_TTL_MS) return hit.value;
  const value = projectPrs(db, path).map((s) => ({ number: s.pr.number, url: s.pr.url, state: s.pr.state, needsPull: s.needsPull, ready: s.ready, ...(s.reason ? { reason: s.reason } : {}) }));
  prCache.set(path, { at: Date.now(), value });
  return value;
}

export function projectRows(db: DatabaseSync): ProjectRow[] {
  const rows = db.prepare(`
    SELECT pr.name, pr.path, pr.exposure, pr.scanned_at,
      (SELECT count(DISTINCT u.package_id) FROM uses u JOIN components c ON c.id = u.component_id WHERE c.project_id = pr.id) AS pkgs
    FROM projects pr`).all() as any[];
  const hostStmt = db.prepare("SELECT DISTINCT value FROM infra WHERE project_id = (SELECT id FROM projects WHERE name = ?) AND kind IN ('host','domain','distribution')");

  const openBy = new Map<string, Map<string, Finding>>();
  for (const f of findings(db)) for (const h of f.hits) {
    if (!openBy.has(h.project)) openBy.set(h.project, new Map());
    openBy.get(h.project)!.set(key(f), f);
  }
  const rules = loadAcceptances(db);
  const acceptedBy = new Map<string, Set<string>>();
  for (const f of findings(db, { includeAccepted: true })) for (const h of f.hits) {
    if (rules.some((a) => acceptanceCovers(a, f, h.project))) acceptedBy.set(h.project, (acceptedBy.get(h.project) ?? new Set()).add(key(f)));
  }
  const issues = new Map<string, number>();
  for (const i of audit(db)) if (i.severity !== "LOW") issues.set(i.project, (issues.get(i.project) ?? 0) + 1);

  return rows.map((r) => {
    const mine = [...(openBy.get(r.name)?.values() ?? [])];
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, mine.filter((f) => f.severity === s).length])) as Record<Severity, number>;
    const accepted = acceptedBy.get(r.name)?.size ?? 0;
    return {
      name: r.name, path: r.path, exposure: r.exposure, packages: r.pkgs, open: mine.length, bySeverity, accepted,
      status: statusOf(mine.length, accepted),
      auditIssues: issues.get(r.name) ?? 0,
      hosts: (hostStmt.all(r.name) as { value: string }[]).map((h) => h.value),
      scannedAt: r.scanned_at,
      prs: prsOf(db, r.path),
    };
  });
}

const OVERVIEW_TTL_MS = 15_000;
let overviewCache: { at: number; value: ReturnType<typeof buildOverview> } | null = null;

/** Cached briefly: the page polls while jobs run, and building this reads the whole graph. */
export function overview(db: DatabaseSync) {
  if (!overviewCache || Date.now() - overviewCache.at > OVERVIEW_TTL_MS) overviewCache = { at: Date.now(), value: buildOverview(db) };
  return overviewCache.value;
}

function buildOverview(db: DatabaseSync) {
  const projects = projectRows(db);
  const list = findings(db);
  const checked = db.prepare("SELECT max(checked_at) AS t FROM packages").get() as { t: string | null };
  return {
    projects,
    totals: {
      projects: projects.length,
      open: list.length,
      critical: list.filter((f) => f.severity === "CRITICAL").length,
      high: list.filter((f) => f.severity === "HIGH").length,
      moderate: list.filter((f) => f.severity === "MODERATE").length,
      clean: projects.filter((p) => p.status === "clean").length,
      accepted: acceptedCount(db), // unique findings: a repo inside a parent project isn't counted twice
      prs: projects.reduce((n, p) => n + p.prs.filter((s) => !s.needsPull).length, 0),
    },
    lastChecked: checked.t,
  };
}

export function projectDetail(db: DatabaseSync, name: string) {
  const row = projectRows(db).find((p) => p.name === name);
  if (!row) throw new Error(`No project named "${name}".`);
  const plan = planFixes(db, name);
  const worst = (a: string, b: string) => (SEVERITIES.indexOf(a as Severity) <= SEVERITIES.indexOf(b as Severity) ? a : b);
  // One entry per package + version: the same one can sit in several lockfiles.
  const packages = new Map<string, any>();
  for (const f of plan.fixes) {
    const k = `${f.name}@${f.from}`;
    // cargo-parent only works if a newer parent happens to exist, so it's an attempt, not a promise.
    const kind = f.strategy === "manual" ? "manual" : f.strategy === "cargo-parent" ? "try" : f.breaking ? "major" : "auto";
    const e = packages.get(k) ?? { name: f.name, from: f.from, to: f.to, severity: f.severity, kind, note: f.note, vulns: [] as string[], lockfiles: [] as string[] };
    e.severity = worst(e.severity, f.severity);
    e.vulns = [...new Set([...e.vulns, ...f.vulns])];
    e.lockfiles = [...new Set([...e.lockfiles, f.component])];
    // The cautious label wins when lockfiles disagree.
    if (kind === "manual" || (kind === "major" && e.kind === "auto")) e.kind = kind;
    packages.set(k, e);
  }
  const acceptances = loadAcceptances(db).filter((a) => a.projects.includes(name)).map((a) => ({
    name: a.name, version: a.version, reason: a.reason, expires: a.expires, vulnIds: a.vulnIds, expired: new Date(a.expires) <= new Date(),
  }));
  return {
    project: row,
    packages: [...packages.values()].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.name.localeCompare(b.name)),
    acceptances,
    git: gitState(row.path),
  };
}

/** Repos in this project's folder: itself, or the ones inside it (VeilSuite holds 8, TallyBook holds 1). */
export function reposIn(path: string, depth = 3): string[] {
  if (existsSync(join(path, ".git"))) return [path];
  if (depth === 0) return [];
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((e) => e.isDirectory() && !e.name.startsWith(".") && e.name !== "node_modules" && e.name !== "target")
    .flatMap((e) => reposIn(join(path, e.name), depth - 1));
}

/** What the page needs to describe a project's git setup. Null only when no repo is there at all. */
function gitState(path: string) {
  const git = (repo: string, ...args: string[]) => {
    try {
      return execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 5000 }).trim();
    } catch {
      return null;
    }
  };
  const repos = reposIn(path);
  if (!repos.length) return null;
  const remotes = repos.map((r) => git(r, "remote", "get-url", "origin")).filter(Boolean) as string[];
  return {
    repos: repos.length,
    branch: repos.length === 1 ? git(repos[0], "branch", "--show-current") || "(detached)" : null,
    onGithub: remotes.some((r) => /github\.com[:/]/.test(r)),
    uncommitted: repos.reduce((n, r) => n + (git(r, "status", "--porcelain", "--untracked-files=no") ?? "").split("\n").filter(Boolean).length, 0),
  };
}

/** Adds downgrade hints to packages with no fixed version. Runs during Check, since it needs the network. */
export async function withDowngradeHints<T extends { project: { path: string }; packages: any[] }>(detail: T): Promise<T> {
  await Promise.all(detail.packages.filter((f) => !f.to).map(async (f) => {
    const hint = await findDowngrade({ name: f.name, version: f.from, lockPaths: f.lockfiles.map((l: string) => join(detail.project.path, l)) });
    if (hint) f.downgrade = hint;
  }));
  return detail;
}

export function findingsView(db: DatabaseSync) {
  return findings(db).map((f) => ({
    id: f.cve ?? f.vulnId, url: f.url, severity: f.severity, risk: f.risk, name: f.name, version: f.version, ecosystem: f.ecosystem, fixed: f.fixed, summary: f.summary,
    projects: [...new Set(f.hits.map((h) => h.project))],
  }));
}

export function auditView(db: DatabaseSync) {
  return audit(db).map((i) => ({ severity: i.severity, category: CATEGORY_LABEL[i.category] ?? i.category, project: i.project, title: i.title, detail: i.detail ?? "", source: i.source ?? "" }));
}

export function infraView(db: DatabaseSync) {
  return db.prepare(`SELECT pr.name AS project, i.kind, i.value, i.source, i.warning FROM infra i JOIN projects pr ON pr.id = i.project_id
    WHERE i.warning IS NOT NULL ORDER BY pr.name, i.kind`).all();
}

// ---------------------------------------------------------------- the fix pipeline

export const PIPELINE = ["pull", "branch", "fix", "verify", "commit", "push", "pr"] as const;
export type Step = (typeof PIPELINE)[number];

/** Which pipeline step a line from the fix engine means has been reached. */
export function stepOf(line: string): Step | null {
  if (/^opened PR /.test(line)) return "pr";
  if (/^pushed /.test(line)) return "push";
  if (/^committed on |^same change as /.test(line)) return "commit";
  if (/^[✓✗≈] |^checking whether /.test(line)) return "verify";
  if (/^edited |lockfile updated|^(cargo-update|cargo-parent|dotnet-add|pip-pin|uv-upgrade|go-get|gradle-edit): /.test(line)) return "fix";
  if (/^working in a separate worktree/.test(line)) return "branch";
  if (/^PR mode:|^no PR possible/.test(line)) return "pull";
  return null;
}
