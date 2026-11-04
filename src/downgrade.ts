// "No fix yet, but an older version might not have this bug." A hint for a human, never applied automatically.
//
// An advisory saying a bug was introduced in X doesn't prove older versions are safe. deepmerge's advisory says 4.2.0,
// but 4.2.0 is where the protection was ADDED: 4.1.2 fails the same attack, it just has no advisory filed against it.
// So this only speaks up when several checks agree, stays silent when it can't check, and always says "unverified".

import { readFileSync } from "node:fs";

const FROM_THE_START = new Set(["0", "0.0.0", "0.0.0-0"]);

type Parsed = [number, number, number];

/** Plain x.y.z only. Prereleases and anything unusual return null, and null never qualifies as a candidate. */
export function parseVersion(v: string): Parsed | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function compare(a: Parsed, b: Parsed): number {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

/** One comparator. Returns null when it's a form we don't understand, which callers treat as "can't verify". */
function comparatorAllows(c: string, v: Parsed): boolean | null {
  if (c === "*" || c === "" || c === "x" || c === "latest") return true;
  const m = /^(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/.exec(c);
  if (!m) return null;
  const [, op = "", maj, min, pat] = m;
  const wild = (s?: string) => s === undefined || s === "x" || s === "*";
  const base: Parsed = [Number(maj), wild(min) ? 0 : Number(min), wild(pat) ? 0 : Number(pat)];
  const cmp = compare(v, base);
  switch (op) {
    case ">=": return cmp >= 0;
    case "<=": return cmp <= 0;
    case ">": return cmp > 0;
    case "<": return cmp < 0;
    case "~":
      if (cmp < 0 || v[0] !== base[0]) return false;
      return wild(min) || v[1] === base[1];
    case "^":
      if (cmp < 0) return false;
      if (base[0] > 0) return v[0] === base[0];
      if (base[1] > 0 || !wild(min)) return v[0] === 0 && v[1] === base[1] && (base[1] > 0 || wild(pat) || v[2] === base[2]);
      return v[0] === 0;
    default:
      if (wild(min)) return v[0] === base[0];
      if (wild(pat)) return v[0] === base[0] && v[1] === base[1];
      return cmp === 0;
  }
}

/** Does an npm range accept this version? null = a form we can't evaluate. */
export function rangeAllows(range: string, version: string): boolean | null {
  const v = parseVersion(version);
  if (!v) return null;
  let unknown = false;
  for (const alt of range.split("||")) {
    const parts = alt.trim().split(/\s+(?=[\^~<>=]|\d|v\d|\*)/).filter(Boolean);
    if (/\s-\s/.test(alt)) { unknown = true; continue; } // hyphen ranges
    const results = parts.length ? parts.map((c) => comparatorAllows(c.replace(/\s+/g, ""), v)) : [true];
    if (results.includes(false)) continue;
    if (results.includes(null)) { unknown = true; continue; }
    return true;
  }
  return unknown ? null : false;
}

/** Newest stable version older than the earliest "introduced"; null if any advisory goes back to the start. */
export function pickCandidate(allVersions: string[], introduced: string[]): string | null {
  if (!introduced.length || introduced.some((i) => FROM_THE_START.has(i))) return null;
  const floors = introduced.map(parseVersion);
  if (floors.some((f) => !f)) return null;
  const floor = (floors as Parsed[]).sort(compare)[0];
  let best: { raw: string; v: Parsed } | null = null;
  for (const raw of allVersions) {
    const v = parseVersion(raw);
    if (v && compare(v, floor) < 0 && (!best || compare(v, best.v) > 0)) best = { raw, v };
  }
  return best?.raw ?? null;
}

/** Every range anything in a package-lock.json declares for this package. */
export function declaredRanges(lockText: string, name: string): string[] {
  const packages = JSON.parse(lockText).packages ?? {};
  const out = new Set<string>();
  for (const entry of Object.values<any>(packages)) {
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const r = entry?.[field]?.[name];
      if (typeof r === "string") out.add(r);
    }
  }
  return [...out];
}

export interface DowngradeHint {
  version: string;
  introduced: string;
  note: string;
}

async function osvFor(name: string, version: string): Promise<any[]> {
  const r = await fetch("https://api.osv.dev/v1/query", {
    method: "POST",
    body: JSON.stringify({ package: { name, ecosystem: "npm" }, version }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!r.ok) throw new Error(`OSV HTTP ${r.status}`);
  return ((await r.json()) as any).vulns ?? [];
}

const cache = new Map<string, { at: number; hint: DowngradeHint | null }>();
const TTL_MS = 3_600_000;

/**
 * npm + package-lock.json only: other lockfiles don't record what parents require, so the range check can't run.
 * A hint needs: every advisory introduced after some older version; OSV reports nothing on that version; and every
 * declared range accepts it. Any failure, including a network error, means no hint.
 */
export async function findDowngrade(pkg: { name: string; version: string; lockPaths: string[] }): Promise<DowngradeHint | null> {
  const key = `${pkg.name}@${pkg.version}|${pkg.lockPaths.join(",")}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.hint;
  let hint: DowngradeHint | null = null;
  try {
    if (pkg.lockPaths.length && pkg.lockPaths.every((p) => p.endsWith("package-lock.json"))) {
      const vulns = await osvFor(pkg.name, pkg.version);
      const introduced = vulns.flatMap((v) => (v.affected ?? [])
        .filter((a: any) => a.package?.name === pkg.name)
        .flatMap((a: any) => (a.ranges ?? []).flatMap((r: any) => (r.events ?? []).map((e: any) => e.introduced).filter(Boolean))));
      const meta = (await (await fetch(`https://registry.npmjs.org/${pkg.name.replace("/", "%2f")}`, { signal: AbortSignal.timeout(15_000) })).json()) as any;
      const candidate = vulns.length ? pickCandidate(Object.keys(meta.versions ?? {}).filter((v) => !meta.versions[v].deprecated), introduced) : null;
      if (candidate && !(await osvFor(pkg.name, candidate)).length) {
        const ranges = pkg.lockPaths.flatMap((p) => declaredRanges(readFileSync(p, "utf8"), pkg.name));
        if (ranges.length && ranges.every((r) => rangeAllows(r, candidate) === true)) {
          const earliest = introduced.map(String).sort((a, b) => compare(parseVersion(a) ?? [0, 0, 0], parseVersion(b) ?? [0, 0, 0]))[0];
          hint = { version: candidate, introduced: earliest, note: "Unverified: no advisory is filed against it, which can just mean nobody looked. Compare the code and test it before trusting it." };
        }
      }
    }
  } catch {
    hint = null; // silent by design: an unverifiable hint is worse than none
  }
  cache.set(key, { at: Date.now(), hint });
  return hint;
}
