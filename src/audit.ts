// Non-CVE risk: malicious packages, untrusted sources, licenses, deprecated / outdated / abandoned deps, infra config.
// Everything is derived from the graph at query time, so rules can change without rescanning.

import type { DatabaseSync } from "node:sqlite";
import { findings } from "./graph.ts";
import { severityRank } from "./osv.ts";
import type { Exposure, IssueCategory } from "./types.ts";

export interface Issue {
  project: string;
  projectPath: string;
  exposure: Exposure;
  category: IssueCategory;
  severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW";
  title: string;
  detail?: string;
  source?: string;
}

export const CATEGORY_LABEL: Record<IssueCategory, string> = {
  malicious: "Malicious & suspicious packages",
  source: "Untrusted sources / dependency confusion",
  license: "License risk",
  deprecated: "Deprecated packages",
  outdated: "Outdated packages",
  abandoned: "Abandoned packages",
  infra: "Infrastructure & CI config",
};

const ABANDONED_YEARS = 2;

// ---------------------------------------------------------------- licenses

export type LicenseClass = "permissive" | "weak-copyleft" | "copyleft" | "network-copyleft" | "non-commercial" | "unknown";
const ORDER: LicenseClass[] = ["permissive", "weak-copyleft", "unknown", "copyleft", "network-copyleft", "non-commercial"];

function classifyId(id: string): LicenseClass {
  const s = id.trim().replace(/^\(|\)$/g, "").replace(/\+$/, "");
  if (/^(AGPL|SSPL|OSL|RPL|EUPL)/i.test(s)) return "network-copyleft";
  if (/^(GPL|CC-BY-SA)/i.test(s)) return "copyleft";
  if (/^(LGPL|MPL|EPL|CDDL|CPL|MS-RL)/i.test(s)) return "weak-copyleft";
  if (/^(BUSL|Elastic|SSPL|Commons-Clause|CC-BY-NC|CC-BY-ND|PolyForm|Prosperity|JSON)/i.test(s) || /non-?commercial/i.test(s)) return "non-commercial";
  if (/^(MIT|ISC|BSD|0BSD|Apache|Unlicense|CC0|CC-BY-[0-9]|Zlib|BlueOak|Python|PSF|BSL-1\.0|WTFPL|Unicode|OFL|Artistic|PostgreSQL|X11|MIT-0|Ruby|NCSA|AFL|Beerware|curl|libpng|HPND|W3C|BlueOak)/i.test(s)) return "permissive";
  return "unknown";
}

/** SPDX expression -> class. OR: you may pick the friendliest. AND: you must honor the strictest. */
export function classifyLicense(expr: string | undefined): LicenseClass {
  if (!expr || /^(non-standard|NOASSERTION|UNKNOWN|SEE LICENSE)/i.test(expr)) return "unknown";
  const ors = expr.replace(/[()]/g, "").split(/\s+OR\s+/i);
  const classes = ors.map((alt) => {
    const ands = alt.split(/\s+AND\s+/i).map((x) => classifyId(x.replace(/\s+WITH\s+.*/i, "")));
    return ands.sort((a, b) => ORDER.indexOf(b) - ORDER.indexOf(a))[0];
  });
  return classes.sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b))[0];
}

// ---------------------------------------------------------------- audit

export function audit(db: DatabaseSync, opts: { project?: string; category?: string } = {}): Issue[] {
  const projects = db.prepare("SELECT id, name, path, exposure, license FROM projects").all() as any[];
  const byId = new Map(projects.map((p) => [p.id, p]));
  const out: Issue[] = [];
  const push = (p: any, i: Omit<Issue, "project" | "projectPath" | "exposure">) =>
    out.push({ project: p.name, projectPath: p.path, exposure: p.exposure, ...i });

  // Scan-time issues (sources, containers, CI, committed secrets).
  for (const r of db.prepare("SELECT * FROM scan_issues").all() as any[]) {
    push(byId.get(r.project_id), { category: r.category, severity: r.severity, title: r.title, detail: r.detail ?? undefined, source: r.source });
  }

  // Unpinned actions / :latest images (collected as infra warnings during scan).
  const warn = db.prepare("SELECT project_id, kind, value, source, warning FROM infra WHERE warning IS NOT NULL").all() as any[];
  const warnGroups = new Map<string, { p: any; sev: Issue["severity"]; title: string; items: Set<string> }>();
  for (const w of warn) {
    const firstParty = /^(actions|github)\//.test(w.value);
    const key = `${w.project_id}|${w.kind}|${firstParty}`;
    const title = w.kind === "gh-action"
      ? firstParty ? "GitHub-owned actions on mutable tags" : "third-party actions on mutable tags (a hijacked tag runs in your CI with your secrets)"
      : "container images without a pinned tag";
    const g = warnGroups.get(key) ?? { p: byId.get(w.project_id), sev: w.kind === "gh-action" && !firstParty ? "MODERATE" : "LOW", title, items: new Set() };
    g.items.add(w.value.replace(/@.*/, ""));
    warnGroups.set(key, g);
  }
  for (const g of warnGroups.values()) {
    push(g.p, { category: "infra", severity: g.sev, title: `${g.title} (${g.items.size})`, detail: [...g.items].slice(0, 10).join(", ") + ". Pin to a commit SHA." });
  }

  // Malicious: OSV's MAL-* advisories (OpenSSF malicious-packages). Dev deps count: they run on your machine.
  for (const f of findings(db, { includeDev: true })) {
    if (!f.vulnId.startsWith("MAL-")) continue;
    for (const proj of new Set(f.hits.map((h) => h.projectPath))) {
      const p = projects.find((x) => x.path === proj);
      push(p, { category: "malicious", severity: "CRITICAL", title: `MALICIOUS package ${f.name}@${f.version}`,
        detail: `${f.summary}. Remove it, rotate any secrets on machines that installed it. ${f.url}` });
    }
  }

  // Per-project package metadata rules.
  const rows = db.prepare(`
    SELECT c.project_id, p.ecosystem, p.name, p.version, max(u.direct) AS direct, max(u.scope = 'prod') AS prod, p.install_script,
           m.licenses, m.deprecated, m.deprecated_reason, l.latest, l.latest_published
    FROM uses u JOIN components c ON c.id = u.component_id JOIN packages p ON p.id = u.package_id
    LEFT JOIN package_meta m ON m.package_id = p.id
    LEFT JOIN package_latest l ON l.ecosystem = p.ecosystem AND l.name = p.name
    GROUP BY c.project_id, p.id`).all() as any[];
  const perProject = new Map<number, any[]>();
  for (const r of rows) perProject.set(r.project_id, [...(perProject.get(r.project_id) ?? []), r]);

  const cutoff = new Date(Date.now() - ABANDONED_YEARS * 365 * 864e5).toISOString();
  for (const [projectId, list] of perProject) {
    const p = byId.get(projectId);
    if (!p) continue;
    const ownClass = classifyLicense(p.license ?? undefined);

    // Install scripts: code that runs on `npm install`. Not malicious by itself, but it's how most npm malware executes.
    const scripts = [...new Set(list.filter((r) => r.install_script).map((r) => r.name))];
    if (scripts.length) push(p, { category: "malicious", severity: "LOW", title: `${scripts.length} package(s) run code at install time`,
      detail: scripts.slice(0, 12).join(", ") + ". Review new ones; consider `npm config set ignore-scripts true` for untrusted installs." });

    // Licenses (production deps only; dev tooling isn't shipped).
    const buckets = new Map<LicenseClass, string[]>();
    for (const r of list) {
      if (!r.prod || r.licenses == null) continue;
      const lic: string[] = JSON.parse(r.licenses);
      const cls = lic.length ? lic.map((l) => classifyLicense(l)).sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b))[0] : "unknown";
      if (cls !== "permissive" && cls !== "weak-copyleft") buckets.set(cls, [...(buckets.get(cls) ?? []), `${r.name} (${lic.join(" / ") || "none"})`]);
    }
    const shipped = p.exposure !== "local";
    const net = buckets.get("network-copyleft");
    if (net && ownClass !== "network-copyleft") push(p, { category: "license", severity: shipped ? "HIGH" : "MODERATE",
      title: `${net.length} network-copyleft (AGPL/SSPL) dependency(ies)`, detail: `Running this as a service can oblige you to publish your source. ${net.slice(0, 8).join(", ")}` });
    const gpl = buckets.get("copyleft");
    if (gpl && !["copyleft", "network-copyleft"].includes(ownClass)) push(p, { category: "license", severity: p.exposure === "distributed" ? "HIGH" : shipped ? "MODERATE" : "LOW",
      title: `${gpl.length} GPL dependency(ies) in a ${p.license ?? "non-GPL"} project`, detail: `Distributing the app (incl. client-side bundles, APKs, desktop builds) can require releasing it under the GPL. ${gpl.slice(0, 8).join(", ")}` });
    const nc = buckets.get("non-commercial");
    if (nc) push(p, { category: "license", severity: "HIGH", title: `${nc.length} source-available / non-commercial license(s)`, detail: `Not free for commercial use. ${nc.slice(0, 8).join(", ")}` });
    const unk = buckets.get("unknown");
    if (unk && unk.length) push(p, { category: "license", severity: "LOW", title: `${unk.length} dependency(ies) with no recognizable license`, detail: unk.slice(0, 8).join(", ") });

    // Deprecated.
    const dep = list.filter((r) => r.deprecated);
    for (const r of dep.filter((r) => r.direct)) push(p, { category: "deprecated", severity: r.prod ? "MODERATE" : "LOW",
      title: `${r.name}@${r.version} is deprecated`, detail: r.deprecated_reason ?? undefined });
    const depT = dep.filter((r) => !r.direct);
    if (depT.length) push(p, { category: "deprecated", severity: "LOW", title: `${depT.length} transitive dependency(ies) are deprecated`,
      detail: depT.map((r) => `${r.name}@${r.version}`).slice(0, 10).join(", ") });

    // Outdated / abandoned: direct deps only.
    const behind2: string[] = [], behind1: string[] = [];
    const abandoned: string[] = [];
    for (const r of list.filter((x) => x.direct && x.latest)) {
      const gap = majorGap(r.version, r.latest);
      if (gap >= 2) behind2.push(`${r.name} ${r.version} → ${r.latest}`);
      else if (gap === 1) behind1.push(`${r.name} ${r.version} → ${r.latest}`);
      if (r.latest_published && r.latest_published < cutoff) abandoned.push(`${r.name} (last release ${r.latest_published.slice(0, 10)})`);
    }
    if (behind2.length) push(p, { category: "outdated", severity: "MODERATE", title: `${behind2.length} direct dep(s) 2+ major versions behind`, detail: behind2.slice(0, 10).join(", ") });
    if (behind1.length) push(p, { category: "outdated", severity: "LOW", title: `${behind1.length} direct dep(s) one major version behind`, detail: behind1.slice(0, 10).join(", ") });
    if (abandoned.length) push(p, { category: "abandoned", severity: "MODERATE", title: `${abandoned.length} direct dep(s) with no release in ${ABANDONED_YEARS}+ years`,
      detail: abandoned.slice(0, 10).join(", ") + ". Some are just finished; check for open security issues and an active fork." });
  }

  return out
    .filter((i) => i.project && (!opts.project || i.project === opts.project) && (!opts.category || i.category === opts.category))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.category.localeCompare(b.category) || a.project.localeCompare(b.project));
}

/** Major versions between installed and latest (0.x minors count as majors). Negative/NaN → 0. */
export function majorGap(installed: string, latest: string): number {
  const a = installed.replace(/^v/, "").split("."), b = latest.replace(/^v/, "").split(".");
  const [a0, a1] = [Number(a[0]), Number(a[1] ?? 0)], [b0, b1] = [Number(b[0]), Number(b[1] ?? 0)];
  if ([a0, a1, b0, b1].some(Number.isNaN)) return 0;
  if (a0 === 0 && b0 === 0) return Math.max(0, b1 - a1);
  if (a0 === 0) return b0; // 0.x → N.x
  return Math.max(0, b0 - a0);
}
