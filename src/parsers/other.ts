// Rust, .NET, Python, Go and Gradle/Maven parsers.
// Each returns the packages it can see plus any edges the format records.

import type { Ecosystem, Edge, Pkg, Scope } from "../types.ts";
import { pkgKey } from "../types.ts";

interface Result {
  packages: Pkg[];
  edges: Edge[];
}

const pkg = (ecosystem: Ecosystem, name: string, version: string, direct: boolean, scope: Scope = "prod"): Pkg => ({
  ecosystem, name, version, direct, scope,
});

/** Minimal TOML reader for lockfiles: returns every [[package]] table as flat key/values. */
function tomlPackages(text: string): Record<string, any>[] {
  const out: Record<string, any>[] = [];
  let cur: Record<string, any> | null = null;
  let arrayKey: string | null = null;
  let arrayBuf = "";
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (arrayKey) {
      arrayBuf += " " + line;
      if (line.startsWith("]") || line.endsWith("]")) {
        if (cur) cur[arrayKey] = [...arrayBuf.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
        arrayKey = null;
      }
      continue;
    }
    if (line === "[[package]]") {
      cur = {};
      out.push(cur);
      continue;
    }
    if (line.startsWith("[")) {
      cur = null; // some other table ([metadata], [package.dependencies] ...)
      continue;
    }
    if (!cur) continue;
    const m = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.*)$/);
    if (!m) continue;
    const [, key, val] = m;
    if (val.startsWith("[")) {
      if (val.endsWith("]")) cur[key] = [...val.matchAll(/"([^"]*)"/g)].map((x) => x[1]);
      else {
        arrayKey = key;
        arrayBuf = val;
      }
    } else if (val.startsWith('"')) cur[key] = val.replace(/^"|"\s*(#.*)?$/g, "");
    else cur[key] = val;
  }
  return out;
}

// ---------------------------------------------------------------- Cargo.lock

export function parseCargoLock(text: string): Result {
  const tables = tomlPackages(text);
  const packages: Pkg[] = [];
  const edges: Edge[] = [];
  // Resolve "name" or "name version" references to name@version.
  const byName = new Map<string, string[]>();
  for (const t of tables) byName.set(t.name, [...(byName.get(t.name) ?? []), t.version]);
  const ref = (s: string) => {
    const [name, version] = s.split(" ");
    return pkgKey(name, version ?? byName.get(name)?.[0] ?? "");
  };

  const local = tables.filter((t) => !t.source); // workspace crates
  const directNames = new Set(local.flatMap((t) => (t.dependencies ?? []).map((d: string) => d.split(" ")[0])));
  for (const t of tables) {
    if (!t.source?.startsWith("registry+")) continue; // skip local + git crates (not in OSV)
    packages.push(pkg("crates.io", t.name, t.version, directNames.has(t.name)));
    for (const d of t.dependencies ?? []) edges.push({ parent: pkgKey(t.name, t.version), child: ref(d) });
  }
  return { packages, edges };
}

// ---------------------------------------------------------------- NuGet

export function parseNugetLock(text: string): Result {
  const lock = JSON.parse(text);
  const seen = new Map<string, Pkg>();
  const edges: Edge[] = [];
  for (const framework of Object.values<any>(lock.dependencies ?? {})) {
    const versions = new Map<string, string>();
    for (const [name, e] of Object.entries<any>(framework)) if (e.resolved) versions.set(name.toLowerCase(), e.resolved);
    for (const [name, e] of Object.entries<any>(framework)) {
      if (!e.resolved || e.type === "Project") continue;
      const key = pkgKey(name, e.resolved);
      if (!seen.has(key)) seen.set(key, pkg("NuGet", name, e.resolved, e.type === "Direct"));
      for (const dep of Object.keys(e.dependencies ?? {})) {
        const v = versions.get(dep.toLowerCase());
        if (v) edges.push({ parent: key, child: pkgKey(dep, v) });
      }
    }
  }
  return { packages: [...seen.values()], edges };
}

/** .csproj / Directory.Packages.props: direct references only. */
export function parseCsproj(text: string, central: Map<string, string> = new Map()): Result {
  const packages: Pkg[] = [];
  const re = /<PackageReference\b([^>]*?)(?:\/>|>([\s\S]*?)<\/PackageReference>)/g;
  for (const m of text.matchAll(re)) {
    const attrs = m[1];
    const name = attrs.match(/\bInclude\s*=\s*"([^"]+)"/)?.[1];
    const version =
      attrs.match(/\bVersion\s*=\s*"([^"]+)"/)?.[1] ??
      m[2]?.match(/<Version>([^<]+)<\/Version>/)?.[1] ??
      (name ? central.get(name.toLowerCase()) : undefined);
    const dev = /PrivateAssets\s*=\s*"all"/i.test(m[0]) || /<PrivateAssets>all</i.test(m[0]);
    if (name && version && /^\d/.test(version)) packages.push(pkg("NuGet", name, version.replace(/[\[\]()]/g, ""), true, dev ? "dev" : "prod"));
  }
  return { packages, edges: [] };
}

export function parseCentralVersions(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const m of text.matchAll(/<PackageVersion\b[^>]*\bInclude\s*=\s*"([^"]+)"[^>]*\bVersion\s*=\s*"([^"]+)"/g)) {
    map.set(m[1].toLowerCase(), m[2]);
  }
  return map;
}

// ---------------------------------------------------------------- Python

const normPy = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "-");

/** requirements.txt: only exact pins (==) can be checked. */
export function parseRequirements(text: string, scope: Scope = "prod"): Result {
  const packages: Pkg[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)/);
    if (m) packages.push(pkg("PyPI", normPy(m[1]), m[2], true, scope));
  }
  return { packages, edges: [] };
}

/** poetry.lock and uv.lock share the [[package]] name/version shape. */
export function parsePyLock(text: string, directNames: Set<string>): Result {
  const tables = tomlPackages(text);
  const packages: Pkg[] = [];
  for (const t of tables) {
    if (!t.name || !t.version) continue;
    if (t.source && /editable|virtual|directory/.test(String(t.source))) continue;
    const n = normPy(t.name);
    packages.push(pkg("PyPI", n, t.version, directNames.has(n), t.category === "dev" ? "dev" : "prod"));
  }
  return { packages, edges: [] };
}

export function parsePipfileLock(text: string): Result {
  const lock = JSON.parse(text);
  const packages: Pkg[] = [];
  for (const [section, scope] of [["default", "prod"], ["develop", "dev"]] as const) {
    for (const [name, e] of Object.entries<any>(lock[section] ?? {})) {
      const v = String(e.version ?? "").replace(/^==/, "");
      if (v) packages.push(pkg("PyPI", normPy(name), v, false, scope));
    }
  }
  return { packages, edges: [] };
}

/** Direct dependency names from pyproject.toml (PEP 621 + poetry tables). */
export function pyprojectDirectNames(text: string): Set<string> {
  const names = new Set<string>();
  for (const m of text.matchAll(/^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)[^"]*"\s*,?\s*$/gm)) names.add(normPy(m[1]));
  let inPoetry = false;
  for (const line of text.split("\n")) {
    if (line.startsWith("[")) inPoetry = /^\[tool\.poetry\.(group\.[^.]+\.)?(dev-)?dependencies\]/.test(line);
    else if (inPoetry) {
      const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/);
      if (m && m[1] !== "python") names.add(normPy(m[1]));
    }
  }
  return names;
}

// ---------------------------------------------------------------- Go

export function parseGoMod(text: string): Result {
  const packages: Pkg[] = [];
  const add = (line: string) => {
    const m = line.trim().match(/^([^\s]+)\s+(v[^\s]+)(\s*\/\/\s*indirect)?/);
    if (m) packages.push(pkg("Go", m[1], m[2].replace(/^v/, ""), !m[3]));
  };
  let inBlock = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("require (")) inBlock = true;
    else if (inBlock && line === ")") inBlock = false;
    else if (inBlock) add(line);
    else if (line.startsWith("require ")) add(line.slice("require ".length));
  }
  // OSV's Go ecosystem wants versions without the leading "v".
  return { packages, edges: [] };
}

// ---------------------------------------------------------------- Gradle / Maven

/** build.gradle(.kts): "group:artifact:version" coordinates (direct deps only). */
export function parseGradle(text: string, catalog: Map<string, string> = new Map()): Result {
  const packages: Pkg[] = [];
  const configRe = /\b(implementation|api|compileOnly|runtimeOnly|kapt|ksp|annotationProcessor|testImplementation|androidTestImplementation|debugImplementation|classpath)\b\s*\(?\s*(.+)/g;
  for (const m of text.matchAll(configRe)) {
    const config = m[1];
    const scope: Scope = /test|debug/i.test(config) ? "dev" : "prod";
    const coord = m[2].match(/["']([\w.-]+):([\w.-]+):([\w.+-]+)["']/);
    if (coord && /^\d/.test(coord[3])) {
      packages.push(pkg("Maven", `${coord[1]}:${coord[2]}`, coord[3], true, scope));
      continue;
    }
    // Version-catalog reference: libs.androidx.core.ktx
    const ref = m[2].match(/\blibs\.([\w.]+)/);
    const fromCatalog = ref && catalog.get(ref[1].replace(/\./g, "-"));
    if (fromCatalog) {
      const [g, a, v] = fromCatalog.split(":");
      packages.push(pkg("Maven", `${g}:${a}`, v, true, scope));
    }
  }
  return { packages, edges: [] };
}

/** gradle/libs.versions.toml -> alias ("androidx-core-ktx") -> "group:artifact:version" */
export function parseVersionCatalog(text: string): Map<string, string> {
  const versions = new Map<string, string>();
  const libs = new Map<string, string>();
  let section = "";
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    const sec = line.match(/^\[(\w+)\]$/);
    if (sec) {
      section = sec[1];
      continue;
    }
    const kv = line.match(/^([\w.-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const [, key, val] = kv;
    if (section === "versions") versions.set(key, val.replace(/^"|"$/g, ""));
    if (section === "libraries") {
      const module = val.match(/module\s*=\s*"([^"]+)"/)?.[1];
      const group = val.match(/group\s*=\s*"([^"]+)"/)?.[1];
      const name = val.match(/name\s*=\s*"([^"]+)"/)?.[1];
      const ga = module ?? (group && name ? `${group}:${name}` : undefined);
      const version = val.match(/version\s*=\s*"([^"]+)"/)?.[1] ?? versions.get(val.match(/version\.ref\s*=\s*"([^"]+)"/)?.[1] ?? "");
      const plain = val.match(/^"([\w.-]+:[\w.-]+:[\w.+-]+)"$/)?.[1];
      const coord = plain ?? (ga && version ? `${ga}:${version}` : undefined);
      if (coord) libs.set(key.replace(/[._]/g, "-"), coord);
    }
  }
  return libs;
}
