// npm / pnpm / yarn lockfiles. Lockfiles already contain the full transitive
// tree, so "crawling" is just walking what the package manager resolved.

import { parse as parseYaml } from "yaml";
import type { Edge, Pkg, Scope } from "../types.ts";
import { pkgKey } from "../types.ts";

interface Result {
  packages: Pkg[];
  edges: Edge[];
}

/** Collects packages, de-duplicating and letting "direct"/"prod" win. */
class Collector {
  private map = new Map<string, Pkg>();
  edges: Edge[] = [];
  add(name: string, version: string, direct: boolean, scope: Scope) {
    if (!name || !version) return;
    const key = pkgKey(name, version);
    const prev = this.map.get(key);
    if (prev) {
      prev.direct ||= direct;
      if (scope === "prod") prev.scope = "prod";
    } else {
      this.map.set(key, { ecosystem: "npm", name, version, direct, scope });
    }
  }
  markInstallScript(key: string) {
    const p = this.map.get(key);
    if (p) p.installScript = true;
  }
  edge(parent: string, child: string) {
    if (parent !== child) this.edges.push({ parent, child });
  }
  result(): Result {
    return { packages: [...this.map.values()], edges: this.edges };
  }
}

/** Strips npm aliases / protocols: "npm:foo@1.2.3" -> "1.2.3". Returns null for non-registry versions. */
function cleanVersion(v: unknown): string | null {
  if (typeof v !== "string") return null;
  let s = v.replace(/\(.*$/, ""); // pnpm peer suffix: 1.0.0(react@18)
  if (s.startsWith("npm:")) s = s.slice(s.lastIndexOf("@") + 1);
  if (/^(link|file|workspace|portal|git|github|http|https):/.test(s)) return null;
  return /^\d/.test(s) ? s : null;
}

// ---------------------------------------------------------------- package-lock

export function parsePackageLock(text: string): Result {
  const lock = JSON.parse(text);
  const c = new Collector();

  if (lock.packages) {
    const pkgs: Record<string, any> = lock.packages;
    const root = pkgs[""] ?? {};
    const directNames = new Set([
      ...Object.keys(root.dependencies ?? {}),
      ...Object.keys(root.devDependencies ?? {}),
      ...Object.keys(root.optionalDependencies ?? {}),
    ]);
    // Workspace packages ("packages/foo") also have direct deps.
    for (const [key, entry] of Object.entries(pkgs)) {
      if (key && !key.includes("node_modules/") && entry && !entry.link) {
        for (const n of Object.keys({ ...entry.dependencies, ...entry.devDependencies })) directNames.add(n);
      }
    }

    const nameOf = (key: string, entry: any) =>
      entry.name ?? key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);

    // Node's resolution: look in ./node_modules, then each ancestor's.
    const resolve = (fromKey: string, dep: string): string | null => {
      let base = fromKey;
      for (;;) {
        const cand = (base ? base + "/" : "") + "node_modules/" + dep;
        if (pkgs[cand]) return cand;
        if (!base) return null;
        const i = base.lastIndexOf("/node_modules/");
        base = i === -1 ? "" : base.slice(0, i);
      }
    };

    const keyToId = (key: string): string | null => {
      const e = pkgs[key];
      if (!e || e.link || !e.version) return null;
      const v = cleanVersion(e.version);
      return v ? pkgKey(nameOf(key, e), v) : null;
    };

    for (const [key, entry] of Object.entries(pkgs)) {
      if (!key.includes("node_modules/")) continue;
      const id = keyToId(key);
      if (!id) continue;
      const name = nameOf(key, entry);
      const isTopLevel = key === "node_modules/" + name;
      c.add(name, cleanVersion(entry.version)!, isTopLevel && directNames.has(name), entry.dev ? "dev" : "prod");
      if (entry.hasInstallScript) c.markInstallScript(id);
      for (const dep of Object.keys({ ...entry.dependencies, ...entry.optionalDependencies })) {
        const childKey = resolve(key, dep);
        const childId = childKey && keyToId(childKey);
        if (childId) c.edge(id, childId);
      }
    }
    return c.result();
  }

  // lockfileVersion 1: nested "dependencies" objects with "requires".
  const walk = (deps: Record<string, any>, depth: number, scopeChain: Record<string, any>[]) => {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      const v = cleanVersion(entry.version);
      if (!v) continue;
      c.add(name, v, depth === 0, entry.dev ? "dev" : "prod");
      const chain = entry.dependencies ? [entry.dependencies, ...scopeChain] : scopeChain;
      for (const req of Object.keys(entry.requires ?? {})) {
        const found = chain.find((s) => s[req])?.[req];
        const cv = found && cleanVersion(found.version);
        if (cv) c.edge(pkgKey(name, v), pkgKey(req, cv));
      }
      if (entry.dependencies) walk(entry.dependencies, depth + 1, chain);
    }
  };
  walk(lock.dependencies, 0, [lock.dependencies ?? {}]);
  return c.result();
}

// ---------------------------------------------------------------- pnpm-lock

/** "/@scope/name@1.2.3(peer@1)" or "@scope/name@1.2.3" -> [name, version] */
function splitPnpmKey(key: string): [string, string] | null {
  const k = key.replace(/^\//, "").replace(/\(.*$/, "");
  const at = k.lastIndexOf("@");
  if (at <= 0) {
    // pnpm v5 style: "/name/1.2.3"
    const m = k.match(/^(.*)\/(\d[^/]*)$/);
    return m ? [m[1], m[2]] : null;
  }
  const v = cleanVersion(k.slice(at + 1));
  return v ? [k.slice(0, at), v] : null;
}

export function parsePnpmLock(text: string): Result {
  const lock: any = parseYaml(text) ?? {};
  const c = new Collector();

  // Direct deps from importers (v6+) or top-level (v5).
  const importers: Record<string, any> = lock.importers ?? { ".": lock };
  const directDev = new Set<string>();
  for (const imp of Object.values(importers)) {
    for (const [field, scope] of [
      ["dependencies", "prod"],
      ["optionalDependencies", "prod"],
      ["devDependencies", "dev"],
    ] as const) {
      for (const [name, spec] of Object.entries<any>(imp?.[field] ?? {})) {
        const v = cleanVersion(typeof spec === "string" ? spec : spec?.version);
        if (!v) continue;
        c.add(name, v, true, scope);
        if (scope === "dev") directDev.add(pkgKey(name, v));
      }
    }
  }

  // v9 keeps deps in "snapshots"; older versions keep them in "packages".
  const graph: Record<string, any> = lock.snapshots ?? lock.packages ?? {};
  const meta: Record<string, any> = lock.packages ?? {};
  for (const [key, entry] of Object.entries<any>(graph)) {
    const nv = splitPnpmKey(key);
    if (!nv) continue;
    const [name, version] = nv;
    const devFlag = meta[key]?.dev ?? entry?.dev;
    c.add(name, version, false, devFlag === true ? "dev" : "prod");
    if (meta[key]?.requiresBuild || meta[key.replace(/\(.*$/, "")]?.requiresBuild) c.markInstallScript(pkgKey(name, version));
    for (const [dep, ver] of Object.entries<any>({ ...entry?.dependencies, ...entry?.optionalDependencies })) {
      const v = cleanVersion(ver);
      if (v) c.edge(pkgKey(name, version), pkgKey(dep, v));
      else {
        // v5 can put "/name/1.2.3" style refs here.
        const alt = typeof ver === "string" ? splitPnpmKey(ver) : null;
        if (alt) c.edge(pkgKey(name, version), pkgKey(alt[0], alt[1]));
      }
    }
  }
  return c.result();
}

// ---------------------------------------------------------------- yarn.lock

/** "@scope/name@^1.0.0" -> "@scope/name" */
function specName(spec: string): string {
  const s = spec.trim().replace(/^"|"$/g, "");
  const at = s.indexOf("@", 1);
  return at === -1 ? s : s.slice(0, at);
}

export function parseYarnLock(text: string, manifest?: any): Result {
  const c = new Collector();
  const direct = new Map<string, Scope>();
  for (const n of Object.keys(manifest?.dependencies ?? {})) direct.set(n, "prod");
  for (const n of Object.keys(manifest?.optionalDependencies ?? {})) direct.set(n, "prod");
  for (const n of Object.keys(manifest?.devDependencies ?? {})) if (!direct.has(n)) direct.set(n, "dev");

  type Entry = { specs: string[]; version: string; deps: Record<string, string> };
  const entries: Entry[] = [];

  if (text.includes("__metadata:")) {
    // Yarn berry: valid YAML.
    const doc: Record<string, any> = parseYaml(text) ?? {};
    for (const [header, e] of Object.entries(doc)) {
      if (header === "__metadata" || !e?.version) continue;
      if (/@(workspace|link|portal|file):/.test(header)) continue;
      entries.push({ specs: header.split(",").map((s) => s.trim()), version: e.version, deps: e.dependencies ?? {} });
    }
  } else {
    // Yarn classic: its own indentation format.
    let cur: Entry | null = null;
    let inDeps = false;
    for (const raw of text.split("\n")) {
      if (!raw.trim() || raw.startsWith("#")) continue;
      if (!raw.startsWith(" ")) {
        cur = { specs: raw.replace(/:$/, "").split(",").map((s) => s.trim().replace(/^"|"$/g, "")), version: "", deps: {} };
        entries.push(cur);
        inDeps = false;
      } else if (cur) {
        const line = raw.trim();
        const indent = raw.length - raw.trimStart().length;
        if (indent === 2) {
          inDeps = line === "dependencies:" || line === "optionalDependencies:";
          const m = line.match(/^version "?([^"]+)"?$/);
          if (m) cur.version = m[1];
        } else if (inDeps && indent >= 4) {
          const m = line.match(/^"?([^"\s]+)"?\s+"?([^"]+)"?$/);
          if (m) cur.deps[m[1]] = m[2];
        }
      }
    }
  }

  // spec ("name@range") -> resolved version
  const resolved = new Map<string, string>();
  for (const e of entries) for (const s of e.specs) resolved.set(s.replace(/^"|"$/g, ""), e.version);
  const lookup = (name: string, range: string) =>
    resolved.get(`${name}@${range}`) ?? resolved.get(`${name}@npm:${range}`);

  for (const e of entries) {
    const v = cleanVersion(e.version);
    if (!v) continue;
    const name = specName(e.specs[0]).replace(/@npm$/, "");
    const scope = direct.get(name);
    c.add(name, v, scope !== undefined, scope ?? "prod");
    for (const [dep, range] of Object.entries(e.deps)) {
      const cv = cleanVersion(lookup(dep, range));
      if (cv) c.edge(pkgKey(name, v), pkgKey(dep, cv));
    }
  }
  return c.result();
}
