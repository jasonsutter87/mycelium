// deps.dev (Google Open Source Insights): free, no key, all six ecosystems.
// Per exact version: licenses, deprecation, publish date. Per package: the newest release.

import type { DatabaseSync } from "node:sqlite";
import { tx } from "./db.ts";
import { fetchRetry } from "./net.ts";

const API = "https://api.deps.dev";
const SYSTEM: Record<string, string> = { npm: "NPM", "crates.io": "CARGO", NuGet: "NUGET", PyPI: "PYPI", Go: "GO", Maven: "MAVEN" };
const BATCH = 1000;
const STALE_DAYS = 7;

async function post(url: string, body: unknown): Promise<any> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetchRetry(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    if (res.ok) return res.json();
    if (attempt >= 3 || (res.status < 500 && res.status !== 429)) throw new Error(`deps.dev ${res.status}: ${(await res.text()).slice(0, 200)}`);
    await new Promise((r) => setTimeout(r, 1500 * 2 ** attempt));
  }
}
async function get(url: string): Promise<any> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetchRetry(url);
    if (res.ok) return res.json();
    if (res.status === 404) return null;
    if (attempt >= 3) return null;
    await new Promise((r) => setTimeout(r, 1500 * 2 ** attempt));
  }
}

/** Fetches metadata for packages that have none (or stale). Returns counts for logging. */
export async function enrich(db: DatabaseSync, log: (s: string) => void = () => {}) {
  const cutoff = new Date(Date.now() - STALE_DAYS * 864e5).toISOString();

  // 1. Version metadata, in batches.
  const need = db.prepare(`
    SELECT DISTINCT p.id, p.ecosystem, p.name, p.version FROM packages p JOIN uses u ON u.package_id = p.id
    LEFT JOIN package_meta m ON m.package_id = p.id WHERE m.package_id IS NULL OR m.fetched_at < ?`).all(cutoff) as any[];
  if (need.length) log(`Fetching license/deprecation data for ${need.length} package versions from deps.dev…`);
  const now = new Date().toISOString();
  const up = db.prepare(`INSERT INTO package_meta (package_id, licenses, deprecated, deprecated_reason, published_at, fetched_at)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(package_id) DO UPDATE SET licenses = excluded.licenses, deprecated = excluded.deprecated,
    deprecated_reason = excluded.deprecated_reason, published_at = excluded.published_at, fetched_at = excluded.fetched_at`);
  for (let i = 0; i < need.length; i += BATCH) {
    const chunk = need.slice(i, i + BATCH);
    const byKey = new Map(chunk.map((p) => [`${SYSTEM[p.ecosystem]}|${p.name}|${p.version}`, p]));
    let pageToken: string | undefined;
    const results: any[] = [];
    do {
      const res = await post(`${API}/v3alpha/versionbatch`, {
        requests: chunk.map((p) => ({ versionKey: { system: SYSTEM[p.ecosystem], name: p.name, version: p.version } })),
        ...(pageToken ? { pageToken } : {}),
      });
      results.push(...(res.responses ?? []));
      pageToken = res.nextPageToken || undefined;
    } while (pageToken);
    tx(db, () => {
      const seen = new Set<number>();
      for (const r of results) {
        const k = r.request?.versionKey;
        const p = k && byKey.get(`${k.system}|${k.name}|${k.version}`);
        if (!p) continue;
        seen.add(p.id);
        const v = r.version;
        up.run(p.id, JSON.stringify(v?.licenses ?? []), v?.isDeprecated ? 1 : 0, v?.deprecatedReason || null, v?.publishedAt ?? null, now);
      }
      // Unknown to deps.dev (private, yanked, too new): record so we don't refetch every run.
      for (const p of chunk) if (!seen.has(p.id)) up.run(p.id, "[]", 0, null, null, now);
    });
  }

  // 2. Newest release, for direct dependencies only (outdated / abandoned are about what you chose).
  const names = db.prepare(`
    SELECT DISTINCT p.ecosystem, p.name FROM packages p JOIN uses u ON u.package_id = p.id
    LEFT JOIN package_latest l ON l.ecosystem = p.ecosystem AND l.name = p.name
    WHERE u.direct = 1 AND (l.name IS NULL OR l.fetched_at < ?)`).all(cutoff) as { ecosystem: string; name: string }[];
  if (names.length) log(`Fetching latest versions for ${names.length} direct dependencies…`);
  const upLatest = db.prepare(`INSERT INTO package_latest (ecosystem, name, latest, latest_published, fetched_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT DO UPDATE SET latest = excluded.latest, latest_published = excluded.latest_published, fetched_at = excluded.fetched_at`);
  const rows: [string, string, string | null, string | null][] = [];
  let i = 0;
  let skipped = 0;
  await Promise.all(Array.from({ length: 12 }, async () => {
    while (i < names.length) {
      const n = names[i++];
      let j: any;
      try {
        j = await get(`${API}/v3/systems/${SYSTEM[n.ecosystem].toLowerCase()}/packages/${encodeURIComponent(n.name)}`);
      } catch {
        skipped++; // no row saved, so the next run asks again
        continue;
      }
      const versions: any[] = j?.versions ?? [];
      const def = versions.find((v) => v.isDefault) ?? versions.at(-1);
      // "Last activity" = newest publish of any version (a maintained 1.x line counts as alive).
      const newest = versions.map((v) => v.publishedAt).filter(Boolean).sort().at(-1) ?? null;
      rows.push([n.ecosystem, n.name, def?.versionKey?.version ?? null, newest]);
    }
  }));
  tx(db, () => {
    for (const r of rows) upLatest.run(...r, now);
  });
  if (skipped) log(`Couldn't fetch latest versions for ${skipped} of ${names.length} direct dependencies; will retry next run.`);
  return { versions: need.length, latest: names.length, skipped };
}
