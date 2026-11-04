// Questions you ask the graph: what's vulnerable, how bad, where, and why is it even here.

import type { DatabaseSync } from "node:sqlite";
import { EXPOSURE_WEIGHT, type Exposure } from "./types.ts";

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 10, HIGH: 7, MODERATE: 4, LOW: 1, UNKNOWN: 3 };

export interface Hit {
  project: string;
  projectPath: string;
  exposure: Exposure;
  component: string;
  componentId: number;
  direct: boolean;
  scope: string;
}

export interface Finding {
  vulnId: string;
  cve: string | null;
  summary: string;
  severity: string;
  url: string;
  packageId: number;
  ecosystem: string;
  name: string;
  version: string;
  fixed: string | null;
  firstSeen: string;
  hits: Hit[];
  risk: number;
}

/** Every open finding, with the projects it touches, ranked by blast radius. */
/**
 * A finding someone reviewed and chose to live with for now (`mycelium accept`). It stays visible as "accepted",
 * and it's deliberately narrow: named projects only, these exact advisories only, with a reason and an expiry.
 */
export interface Acceptance {
  name: string;
  version?: string;
  vulnIds: string[];
  projects: string[];
  reason: string;
  acceptedAt: string;
  expires: string;
}

export function loadAcceptances(db: DatabaseSync): Acceptance[] {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'accepted'").get() as { value: string } | undefined;
  return JSON.parse(row?.value ?? "[]");
}

export function acceptanceCovers(a: Acceptance, f: { name: string; version: string; vulnId: string }, project: string, now = new Date()): boolean {
  if (new Date(a.expires) <= now) return false;
  if (f.vulnId.startsWith("MAL-")) return false; // a malicious package is never something to live with
  if (a.name !== f.name || (a.version && a.version !== f.version)) return false;
  return a.vulnIds.includes(f.vulnId) && a.projects.includes(project); // a NEW advisory on this package still shows up
}

/** How many open-looking findings are currently accepted, per the same rules findings() applies. */
export function acceptedCount(db: DatabaseSync, opts: { includeDev?: boolean; project?: string } = {}): number {
  const rules = loadAcceptances(db);
  return findings(db, { includeDev: opts.includeDev, includeAccepted: true }).filter((f) =>
    f.hits.some((h) => (!opts.project || h.project === opts.project) && rules.some((a) => acceptanceCovers(a, f, h.project))),
  ).length;
}

export function findings(db: DatabaseSync, opts: { includeDev?: boolean; onlyNew?: boolean; includeAccepted?: boolean } = {}): Finding[] {
  const rules = opts.includeAccepted ? [] : loadAcceptances(db);
  const rows = db.prepare(`
    SELECT pv.vuln_id, pv.fixed, pv.first_seen, pv.notified, v.summary, v.severity, v.aliases, v.url,
           p.id AS package_id, p.ecosystem, p.name, p.version
    FROM package_vulns pv JOIN vulns v ON v.id = pv.vuln_id JOIN packages p ON p.id = pv.package_id
    ${opts.onlyNew ? "WHERE pv.notified = 0" : ""}`).all() as any[];

  const hitsStmt = db.prepare(`
    SELECT pr.name AS project, pr.path, pr.exposure, c.path AS component, c.id AS component_id, u.direct, u.scope
    FROM uses u JOIN components c ON c.id = u.component_id JOIN projects pr ON pr.id = c.project_id
    WHERE u.package_id = ?`);

  const out: Finding[] = [];
  for (const r of rows) {
    let hits = (hitsStmt.all(r.package_id) as any[]).map((h) => ({
      project: h.project, projectPath: h.path, exposure: h.exposure as Exposure, component: h.component,
      componentId: h.component_id, direct: !!h.direct, scope: h.scope,
    }));
    if (!opts.includeDev) hits = hits.filter((h) => h.scope === "prod");
    hits = hits.filter((h) => !rules.some((a) => acceptanceCovers(a, { name: r.name, version: r.version, vulnId: r.vuln_id }, h.project)));
    if (!hits.length) continue;
    const aliases: string[] = JSON.parse(r.aliases);
    const exposure = Math.max(...hits.map((h) => EXPOSURE_WEIGHT[h.exposure]));
    const sev = SEVERITY_WEIGHT[r.severity] ?? 3;
    out.push({
      vulnId: r.vuln_id,
      cve: [r.vuln_id, ...aliases].find((a) => a.startsWith("CVE-")) ?? null,
      summary: r.summary ?? "",
      severity: r.severity,
      url: r.url,
      packageId: r.package_id,
      ecosystem: r.ecosystem,
      name: r.name,
      version: r.version,
      fixed: r.fixed,
      firstSeen: r.first_seen,
      hits,
      // Severity x how exposed the worst-placed project is x how many projects (diminishing).
      risk: Math.round(sev * exposure * (1 + Math.log2(new Set(hits.map((h) => h.project)).size)) * 10) / 10,
    });
  }
  return out.sort((a, b) => b.risk - a.risk);
}

/**
 * Dependency chains from something the project asked for to the target package,
 * e.g. ["next@14.1.0", "postcss@8.4.31"]. Walks edges upward (child -> parent).
 */
export function whyPaths(db: DatabaseSync, componentId: number, packageId: number, limit = 3): string[][] {
  const parents = db.prepare("SELECT parent_id FROM edges WHERE component_id = ? AND child_id = ?");
  const isDirect = db.prepare("SELECT direct FROM uses WHERE component_id = ? AND package_id = ?");
  const label = db.prepare("SELECT name || '@' || version AS l FROM packages WHERE id = ?");
  const name = (id: number) => (label.get(id) as { l: string }).l;

  const paths: string[][] = [];
  const queue: number[][] = [[packageId]];
  const seen = new Set<number>([packageId]);
  while (queue.length && paths.length < limit) {
    const path = queue.shift()!;
    const head = path[0];
    const d = isDirect.get(componentId, head) as { direct: number } | undefined;
    const ps = (parents.all(componentId, head) as { parent_id: number }[]).map((r) => r.parent_id);
    if (d?.direct || !ps.length) {
      paths.push(path.map(name));
      continue;
    }
    for (const p of ps) {
      if (seen.has(p) || path.length > 12) continue;
      seen.add(p);
      queue.push([p, ...path]);
    }
  }
  return paths;
}

/** "Am I affected?": every project using a package (optionally a specific version). */
export function impact(db: DatabaseSync, name: string, version?: string) {
  return db.prepare(`
    SELECT pr.name AS project, pr.exposure, p.ecosystem, p.name, p.version, u.direct, u.scope, c.path AS component,
           c.id AS component_id, p.id AS package_id
    FROM packages p JOIN uses u ON u.package_id = p.id JOIN components c ON c.id = u.component_id
    JOIN projects pr ON pr.id = c.project_id
    WHERE lower(p.name) = lower(?) ${version ? "AND p.version = ?" : ""}
    ORDER BY pr.name, p.version`).all(...(version ? [name, version] : [name])) as any[];
}

/** The command that would move this package to the fixed version. */
export function fixCommand(f: Pick<Finding, "ecosystem" | "name" | "fixed">, direct: boolean, parent?: string): string {
  if (!f.fixed) return "no fixed version published yet: watch the advisory or replace the package";
  const transitive = !direct && parent ? ` (pulled in by ${parent}: update it, or force the version)` : "";
  switch (f.ecosystem) {
    case "npm":
      return direct
        ? `npm install ${f.name}@^${f.fixed}`
        : `npm update ${f.name}  → if still old, add "overrides": { "${f.name}": "^${f.fixed}" }${transitive}`;
    case "crates.io":
      return `cargo update -p ${f.name} --precise ${f.fixed}${transitive}`;
    case "NuGet":
      return `dotnet add package ${f.name} --version ${f.fixed}${transitive}`;
    case "PyPI":
      return `pip install "${f.name}>=${f.fixed}"  (or bump it in pyproject/requirements)${transitive}`;
    case "Go":
      return `go get ${f.name}@v${f.fixed} && go mod tidy`;
    case "Maven":
      return `bump ${f.name} to ${f.fixed} in build.gradle / libs.versions.toml`;
    default:
      return `upgrade ${f.name} to ${f.fixed}`;
  }
}
