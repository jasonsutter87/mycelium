// OSV.dev client. Free, no key, covers npm / crates.io / NuGet / PyPI / Go / Maven
// (it aggregates GitHub Advisories, RustSec, PyPA, Go vulndb, NVD aliases, ...).

import type { DatabaseSync } from "node:sqlite";
import { tx } from "./db.ts";
import { fetchRetry } from "./net.ts";

const API = "https://api.osv.dev/v1";
const BATCH = 1000; // OSV querybatch limit
const CONCURRENCY = 8;

interface PackageRow {
  id: number;
  ecosystem: string;
  name: string;
  version: string;
}

export interface NewFinding {
  packageId: number;
  vulnId: string;
}

async function postJson(url: string, body: unknown): Promise<any> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetchRetry(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    if (res.ok) return res.json();
    if (attempt >= 3 || res.status < 500) throw new Error(`OSV ${res.status}: ${await res.text()}`);
    await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
  }
}

async function getJson(url: string): Promise<any> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetchRetry(url);
    if (res.ok) return res.json();
    if (res.status === 404) return null;
    if (attempt >= 3) throw new Error(`OSV ${res.status} for ${url}`);
    await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
  }
}

async function pool<T>(items: T[], n: number, fn: (t: T) => Promise<void>) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]);
  }));
}

/**
 * Checks every package currently used by any project against OSV.
 * Returns findings that were not in the database before this run.
 */
export async function checkAll(db: DatabaseSync, log: (s: string) => void = () => {}): Promise<NewFinding[]> {
  const pkgs = db
    .prepare("SELECT DISTINCT p.id, p.ecosystem, p.name, p.version FROM packages p JOIN uses u ON u.package_id = p.id")
    .all() as unknown as PackageRow[];
  log(`Checking ${pkgs.length} unique packages against OSV.dev…`);

  // 1. Which vuln ids affect which packages.
  const hits = new Map<number, Map<string, string>>(); // packageId -> vulnId -> modified
  for (let i = 0; i < pkgs.length; i += BATCH) {
    let chunk = pkgs.slice(i, i + BATCH).map((p) => ({ p, token: undefined as string | undefined }));
    while (chunk.length) {
      const res = await postJson(`${API}/querybatch`, {
        queries: chunk.map(({ p, token }) => ({
          package: { ecosystem: p.ecosystem, name: p.name },
          version: p.version,
          ...(token ? { page_token: token } : {}),
        })),
      });
      const next: typeof chunk = [];
      res.results.forEach((r: any, j: number) => {
        const { p } = chunk[j];
        const m = hits.get(p.id) ?? new Map();
        for (const v of r.vulns ?? []) m.set(v.id, v.modified);
        hits.set(p.id, m);
        if (r.next_page_token) next.push({ p, token: r.next_page_token });
      });
      chunk = next;
    }
  }

  // 2. Fetch details for vulns we haven't cached (or that changed).
  const known = new Map(
    (db.prepare("SELECT id, modified FROM vulns").all() as { id: string; modified: string }[]).map((r) => [r.id, r.modified]),
  );
  const wanted = new Map<string, string>();
  for (const m of hits.values()) for (const [id, mod] of m) if (known.get(id) !== mod) wanted.set(id, mod);
  if (wanted.size) log(`Fetching ${wanted.size} advisories…`);

  const details = new Map<string, any>();
  await pool([...wanted.keys()], CONCURRENCY, async (id) => {
    const v = await getJson(`${API}/vulns/${encodeURIComponent(id)}`);
    if (v) details.set(id, v);
  });

  // 3. Persist.
  const now = new Date().toISOString();
  const fresh: NewFinding[] = [];
  const byId = new Map(pkgs.map((p) => [p.id, p]));
  tx(db, () => {
    const upVuln = db.prepare(`
      INSERT INTO vulns (id, summary, severity, aliases, published, modified, url) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET summary = excluded.summary, severity = excluded.severity, aliases = excluded.aliases,
        published = excluded.published, modified = excluded.modified`);
    for (const [id, v] of details) {
      if (v.withdrawn) continue;
      upVuln.run(id, summarize(v), severityOf(v), JSON.stringify(v.aliases ?? []), v.published ?? null,
        // Store querybatch's timestamp: the detail endpoint formats it differently, which would defeat the cache.
        wanted.get(id) ?? v.modified, `https://osv.dev/vulnerability/${id}`);
    }

    const existing = db.prepare("SELECT vuln_id FROM package_vulns WHERE package_id = ?");
    const insPV = db.prepare("INSERT OR IGNORE INTO package_vulns (package_id, vuln_id, fixed, first_seen) VALUES (?, ?, ?, ?)");
    const updFixed = db.prepare("UPDATE package_vulns SET fixed = ? WHERE package_id = ? AND vuln_id = ?");
    const delPV = db.prepare("DELETE FROM package_vulns WHERE package_id = ? AND vuln_id = ?");
    const vulnExists = db.prepare("SELECT 1 FROM vulns WHERE id = ?");
    const markChecked = db.prepare("UPDATE packages SET checked_at = ? WHERE id = ?");

    for (const p of pkgs) {
      const current = hits.get(p.id) ?? new Map();
      const before = new Set((existing.all(p.id) as { vuln_id: string }[]).map((r) => r.vuln_id));
      for (const vulnId of current.keys()) {
        if (!vulnExists.get(vulnId)) continue; // withdrawn or fetch failed
        const v = details.get(vulnId);
        const fixed = v ? fixedVersion(v, byId.get(p.id)!) : undefined;
        if (!before.has(vulnId)) {
          insPV.run(p.id, vulnId, fixed ?? null, now);
          fresh.push({ packageId: p.id, vulnId });
        } else if (fixed) updFixed.run(fixed, p.id, vulnId);
      }
      for (const old of before) if (!current.has(old)) delPV.run(p.id, old); // fixed upstream / withdrawn
      markChecked.run(now, p.id);
    }
  });
  return fresh;
}

export interface PackageVuln { ecosystem: string; name: string; version: string; vulnId: string; severity: string; summary: string; fixed: string | null }

/** Asks about packages that aren't in the graph, like the ones a PR would add. Stores nothing. */
export async function checkPackages(list: { ecosystem: string; name: string; version: string }[]): Promise<PackageVuln[]> {
  const out: PackageVuln[] = [];
  const hits: { p: (typeof list)[number]; id: string }[] = [];
  for (let i = 0; i < list.length; i += BATCH) {
    let chunk = list.slice(i, i + BATCH).map((p) => ({ p, token: undefined as string | undefined }));
    while (chunk.length) {
      const res = await postJson(`${API}/querybatch`, { queries: chunk.map(({ p, token }) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version, ...(token ? { page_token: token } : {}) })) });
      const next: typeof chunk = [];
      res.results.forEach((r: any, j: number) => {
        for (const v of r.vulns ?? []) hits.push({ p: chunk[j].p, id: v.id });
        if (r.next_page_token) next.push({ p: chunk[j].p, token: r.next_page_token });
      });
      chunk = next;
    }
  }
  const details = new Map<string, any>();
  await pool([...new Set(hits.map((h) => h.id))], CONCURRENCY, async (id) => {
    details.set(id, await getJson(`${API}/vulns/${encodeURIComponent(id)}`));
  });
  for (const { p, id } of hits) {
    const v = details.get(id);
    if (!v || v.withdrawn) continue;
    out.push({ ...p, vulnId: id, severity: severityOf(v), summary: summarize(v), fixed: fixedVersion(v, p) ?? null });
  }
  return out;
}

function summarize(v: any): string {
  return (v.summary || v.details?.split("\n")[0] || "").slice(0, 200);
}

// ---------------------------------------------------------------- severity

const RANK = ["UNKNOWN", "LOW", "MODERATE", "HIGH", "CRITICAL"] as const;
export const severityRank = (s: string) => Math.max(0, RANK.indexOf(s as (typeof RANK)[number]));

export function severityOf(v: any): string {
  if (String(v.id ?? "").startsWith("MAL-")) return "CRITICAL"; // OpenSSF malicious-packages: always top priority
  const label = String(v.database_specific?.severity ?? "").toUpperCase();
  if (label === "MEDIUM") return "MODERATE";
  if (RANK.includes(label as any) && label !== "UNKNOWN") return label;
  for (const s of v.severity ?? []) {
    if (s.type === "CVSS_V3" || s.type === "CVSS_V31") {
      const score = cvss3(s.score);
      if (score !== null) return score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MODERATE" : score > 0 ? "LOW" : "UNKNOWN";
    }
  }
  return "UNKNOWN";
}

/** CVSS v3.x base score from a vector string (spec: first.org/cvss/v3.1/specification-document). */
export function cvss3(vector: string): number | null {
  const m = Object.fromEntries(vector.split("/").slice(1).map((kv) => kv.split(":")));
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV as string];
  const AC = { L: 0.77, H: 0.44 }[m.AC as string];
  const UI = { N: 0.85, R: 0.62 }[m.UI as string];
  const changed = m.S === "C";
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR as string];
  const cia = (x: string) => ({ H: 0.56, L: 0.22, N: 0 })[x];
  const C = cia(m.C), I = cia(m.I), A = cia(m.A);
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * AV! * AC! * PR! * UI!;
  const roundUp = (x: number) => Math.ceil(x * 10 - 1e-9) / 10;
  return roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

// ---------------------------------------------------------------- fixed version

export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/), pb = b.split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0", y = pb[i] ?? "0";
    const nx = Number(x), ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Smallest "fixed" event above the installed version, for this exact package. */
export function fixedVersion(v: any, p: { ecosystem: string; name: string; version: string }): string | undefined {
  const fixes: string[] = [];
  for (const a of v.affected ?? []) {
    if (a.package?.ecosystem !== p.ecosystem || a.package?.name?.toLowerCase() !== p.name.toLowerCase()) continue;
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      for (const e of r.events ?? []) if (e.fixed) fixes.push(String(e.fixed).replace(/^v/, ""));
    }
  }
  const above = fixes.filter((f) => compareVersions(f, p.version) > 0).sort(compareVersions);
  return above[0];
}
