// Walks a project folder, runs every parser that applies, and writes the graph to SQLite.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { parsePackageLock, parsePnpmLock, parseYarnLock } from "./parsers/js.ts";
import {
  parseCargoLock, parseCentralVersions, parseCsproj, parseGoMod, parseGradle, parseNugetLock,
  parsePipfileLock, parsePyLock, parseRequirements, parseVersionCatalog, pyprojectDirectNames,
} from "./parsers/other.ts";
import { detectFromFile, gitRemote, parseCompose, parseDockerfile, parseWorkflow } from "./parsers/infra.ts";
import {
  checkCargoLock, checkCompose, checkDockerfile, checkGoMod, checkNugetConfig, checkPackageLock, checkPnpmLock,
  checkPyLock, checkRequirements, checkWorkflow, checkYarnLock, npmrcScopes, projectLicense,
} from "./parsers/checks.ts";
import { execFileSync } from "node:child_process";
import type { Component, Exposure, Infra, ScanIssue } from "./types.ts";
import { pkgKey } from "./types.ts";
import { tx } from "./db.ts";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "target", "dist", "build", "out", "bin", "obj", ".next", ".nuxt", ".svelte-kit",
  ".venv", "venv", "env", "__pycache__", ".gradle", "Pods", ".expo", "vendor", "coverage", ".turbo",
  ".cache", ".idea", ".vscode", "DerivedData", ".godot", ".angular", "Library", "tmp",
]);
const MAX_DEPTH = 7;

const INFRA_FILES = new Set([
  "vercel.json", "netlify.toml", "fly.toml", "wrangler.toml", "wrangler.json", "wrangler.jsonc", "firebase.json",
  "render.yaml", "railway.json", "railway.toml", "Procfile", "CNAME", "Caddyfile", "package.json", "app.json",
  "eas.json", "tauri.conf.json", "project.godot", "build.gradle", "build.gradle.kts", "manifest.json",
  "hugo.toml", "hugo.yaml", "config.toml",
]);

export interface ProjectScan {
  name: string;
  path: string;
  components: Component[];
  infra: Infra[];
  exposure: Exposure;
  warnings: string[];
  issues: ScanIssue[];
  license: string | null;
}

// Folders you've told Mycelium to leave out (`mycelium ignore <folder>`): snapshots, backups, throwaway copies.
let ignored: string[] = [];
export function setIgnored(paths: string[]) {
  ignored = paths;
}
const isIgnored = (p: string) => ignored.some((i) => p === i || p.startsWith(i + "/"));

/** All files under dir (relative paths), skipping build/dependency folders. */
function walk(dir: string, root = dir, depth = 0, out: string[] = []): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (depth < MAX_DEPTH && !isIgnored(full) && !SKIP_DIRS.has(e.name) && (!e.name.startsWith(".") || e.name === ".github" || e.name === ".vercel")) {
        walk(full, root, depth + 1, out);
      }
    } else if (e.isFile()) out.push(relative(root, full));
  }
  return out;
}

const read = (p: string) => {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
};

export function scanProject(path: string): ProjectScan {
  const root = resolve(path);
  const files = walk(root);
  const fileSet = new Set(files);
  const components: Component[] = [];
  const infra: Infra[] = [];
  const warnings: string[] = [];
  const issues: ScanIssue[] = [];
  const has = (rel: string) => fileSet.has(rel);
  // Scoped registries from the nearest .npmrc (same folder, else project root).
  const scopesFor = (dir: string) => {
    const rc = [dir === "." ? ".npmrc" : join(dir, ".npmrc"), ".npmrc"].find(has);
    return rc ? npmrcScopes(read(join(root, rc)) ?? "") : new Map<string, string>();
  };
  const check = (rel: string, fn: () => ScanIssue[]) => tryParse(rel, () => issues.push(...fn()));

  const tryParse = (rel: string, fn: () => void) => {
    try {
      fn();
    } catch (e) {
      warnings.push(`${rel}: ${(e as Error).message.split("\n")[0]}`);
    }
  };
  const comp = (kind: string, rel: string, r: Pick<Component, "packages" | "edges">) => {
    if (r.packages.length) components.push({ kind, path: rel, ecosystem: r.packages[0].ecosystem, ...r });
  };

  // Version catalog for Gradle, if any.
  const catalogRel = files.find((f) => f.endsWith("gradle/libs.versions.toml"));
  const catalog = catalogRel ? parseVersionCatalog(read(join(root, catalogRel)) ?? "") : new Map<string, string>();

  for (const rel of files) {
    const base = basename(rel);
    const dir = dirname(rel);
    const sib = (name: string) => (dir === "." ? name : join(dir, name));
    let cached: string | null = null;
    const text = () => (cached ??= read(join(root, rel)) ?? "");

    // ---- Source checks (dependency confusion, git/http installs) and container/CI config
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") check(rel, () => checkPackageLock(text(), rel, scopesFor(dir)));
    else if (base === "pnpm-lock.yaml") check(rel, () => checkPnpmLock(text(), rel, scopesFor(dir)));
    else if (base === "yarn.lock") check(rel, () => checkYarnLock(text(), rel, scopesFor(dir)));
    else if (base === "Cargo.lock") check(rel, () => checkCargoLock(text(), rel));
    else if (/^requirements.*\.txt$/.test(base)) check(rel, () => checkRequirements(text(), rel));
    else if (base === "poetry.lock" || base === "uv.lock") check(rel, () => checkPyLock(text(), rel));
    else if (/^nuget\.config$/i.test(base)) check(rel, () => checkNugetConfig(text(), rel));
    else if (base === "go.mod") check(rel, () => checkGoMod(text(), rel));
    if (/^(Dockerfile|Containerfile)(\..+)?$|\.Dockerfile$/.test(base)) check(rel, () => checkDockerfile(text(), rel));
    if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(base)) check(rel, () => checkCompose(text(), rel));
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel)) check(rel, () => checkWorkflow(text(), rel));

    // ---- JavaScript (one lockfile per folder; prefer npm > pnpm > yarn)
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
      tryParse(rel, () => comp("npm:package-lock", rel, parsePackageLock(text())));
    } else if (base === "pnpm-lock.yaml" && !has(sib("package-lock.json"))) {
      tryParse(rel, () => comp("npm:pnpm-lock", rel, parsePnpmLock(text())));
    } else if (base === "yarn.lock" && !has(sib("package-lock.json")) && !has(sib("pnpm-lock.yaml"))) {
      tryParse(rel, () => {
        const manifest = has(sib("package.json")) ? JSON.parse(read(join(root, sib("package.json"))) ?? "{}") : undefined;
        comp("npm:yarn-lock", rel, parseYarnLock(text(), manifest));
      });
    } else if (base === "package.json" && !rel.includes("node_modules")) {
      const locked = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"].some((l) => has(sib(l)));
      // Workspace members share the root lockfile; only flag top-level manifests.
      if (!locked && dir === ".") warnings.push(`${rel}: no lockfile, transitive deps unknown (run npm install)`);
    }

    // ---- Rust
    else if (base === "Cargo.lock") tryParse(rel, () => comp("cargo:Cargo.lock", rel, parseCargoLock(text())));

    // ---- .NET
    else if (base === "packages.lock.json") tryParse(rel, () => comp("nuget:packages.lock", rel, parseNugetLock(text())));
    else if (/\.(cs|fs|vb)proj$/.test(base) && !has(sib("packages.lock.json"))) {
      tryParse(rel, () => {
        // Central package management: nearest Directory.Packages.props up the tree.
        let central = new Map<string, string>();
        for (let d = dir; ; d = dirname(d)) {
          const props = d === "." ? "Directory.Packages.props" : join(d, "Directory.Packages.props");
          if (has(props)) {
            central = parseCentralVersions(read(join(root, props)) ?? "");
            break;
          }
          if (d === "." || d === "/") break;
        }
        comp("nuget:csproj", rel, parseCsproj(text(), central));
      });
    }

    // ---- Python
    else if (base === "poetry.lock" || base === "uv.lock") {
      tryParse(rel, () => {
        const direct = has(sib("pyproject.toml")) ? pyprojectDirectNames(read(join(root, sib("pyproject.toml"))) ?? "") : new Set<string>();
        comp(`pypi:${base}`, rel, parsePyLock(text(), direct));
      });
    } else if (base === "Pipfile.lock") tryParse(rel, () => comp("pypi:Pipfile.lock", rel, parsePipfileLock(text())));
    else if (/^requirements.*\.txt$/.test(base) && !["poetry.lock", "uv.lock", "Pipfile.lock"].some((l) => has(sib(l)))) {
      tryParse(rel, () => comp("pypi:requirements", rel, parseRequirements(text(), /dev|test/.test(base) ? "dev" : "prod")));
    }

    // ---- Go
    else if (base === "go.mod") tryParse(rel, () => comp("go:go.mod", rel, parseGoMod(text())));

    // ---- Infra: Docker + CI
    if (/^(Dockerfile|Containerfile)(\..+)?$|\.Dockerfile$/.test(base)) tryParse(rel, () => infra.push(...parseDockerfile(text(), rel)));
    if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(base)) tryParse(rel, () => infra.push(...parseCompose(text(), rel)));
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel)) tryParse(rel, () => infra.push(...parseWorkflow(text(), rel)));

    // ---- Gradle (deps) + hosts/domains/distribution
    if (base === "build.gradle" || base === "build.gradle.kts") {
      tryParse(rel, () => comp("maven:gradle", rel, parseGradle(text(), catalog)));
    }
    if (INFRA_FILES.has(base) || /^(astro|capacitor)\.config\./.test(base) || (base === "project.json" && rel.startsWith(".vercel/"))) {
      tryParse(rel, () => infra.push(...detectFromFile(base, rel, text())));
    }
  }

  // Git remote.
  const gitConfig = existsSync(join(root, ".git", "config")) ? read(join(root, ".git", "config")) : null;
  const remote = gitConfig && gitRemote(gitConfig);
  if (remote) infra.push({ kind: "repo", value: remote, source: ".git/config" });

  // Secrets files committed to git (.env, .env.production …, not .env.example).
  const envFiles = files.filter((f) => /(^|\/)\.env(\.[\w-]+)?$/.test(f) && !/\.(example|sample|template|dist|defaults?)$/.test(f));
  if (envFiles.length && gitConfig) {
    try {
      const tracked = execFileSync("git", ["-C", root, "ls-files", "--", ...envFiles], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })
        .split("\n").filter(Boolean);
      for (const f of tracked) issues.push({ category: "infra", severity: "HIGH", title: "secrets file committed to git", source: f, detail: "Rotate anything in it, then git rm --cached it and add it to .gitignore." });
    } catch {}
  }

  const license = projectLicense({
    packageJson: has("package.json") ? read(join(root, "package.json")) ?? undefined : undefined,
    cargoToml: has("Cargo.toml") ? read(join(root, "Cargo.toml")) ?? undefined : undefined,
    pyproject: has("pyproject.toml") ? read(join(root, "pyproject.toml")) ?? undefined : undefined,
    licenseText: ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"].filter(has).map((f) => read(join(root, f)) ?? "")[0],
  });

  return { name: basename(root), path: root, components, infra: dedupeInfra(infra), exposure: exposureOf(infra), warnings, issues, license };
}

function dedupeInfra(list: Infra[]): Infra[] {
  const seen = new Set<string>();
  return list.filter((i) => {
    const k = `${i.kind}|${i.value}|${i.source}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

const WEB_HOSTS = /vercel|netlify|fly\.io|cloudflare|firebase|render|railway|heroku|github-pages|caddy/;

export function exposureOf(infra: Infra[]): Exposure {
  if (infra.some((i) => i.kind === "domain" || (i.kind === "host" && WEB_HOSTS.test(i.value)))) return "public-web";
  if (infra.some((i) => i.kind === "distribution")) return "distributed";
  if (infra.some((i) => i.kind === "host")) return "self-hosted";
  return "local";
}

/** Is this folder a project root (vs. a folder of projects)? */
export function looksLikeProject(dir: string): boolean {
  const markers = [".git", "package.json", "Cargo.toml", "go.mod", "pyproject.toml", "project.godot"];
  return markers.some((f) => existsSync(join(dir, f))) || readdirSync(dir).some((f) => /\.(sln|csproj)$/.test(f));
}

/** Expands a root into project folders: the root itself if it is one, else its children. */
export function findProjects(root: string): string[] {
  const abs = resolve(root);
  if (looksLikeProject(abs)) return [abs];
  return readdirSync(abs, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !e.name.startsWith(".") && !SKIP_DIRS.has(e.name))
    .map((e) => join(abs, e.name))
    .filter((p) => {
      if (isIgnored(p)) return false;
      try {
        return statSync(p).isDirectory();
      } catch {
        return false;
      }
    });
}

/** Parse one lockfile/manifest's text by its filename (used to read lockfiles straight out of git, e.g. a PR's head). */
export function parseLockText(base: string, text: string): { ecosystem: string; name: string; version: string }[] {
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") return parsePackageLock(text).packages;
  if (base === "pnpm-lock.yaml") return parsePnpmLock(text).packages;
  if (base === "yarn.lock") return parseYarnLock(text).packages;
  if (base === "Cargo.lock") return parseCargoLock(text).packages;
  if (base === "packages.lock.json") return parseNugetLock(text).packages;
  if (/\.(cs|fs|vb)proj$/.test(base)) return parseCsproj(text).packages;
  if (base === "poetry.lock" || base === "uv.lock") return parsePyLock(text, new Set()).packages;
  if (base === "Pipfile.lock") return parsePipfileLock(text).packages;
  if (/^requirements.*\.txt$/.test(base)) return parseRequirements(text).packages;
  if (base === "go.mod") return parseGoMod(text).packages;
  if (base === "build.gradle" || base === "build.gradle.kts") return parseGradle(text).packages;
  return [];
}

export interface ScanSummary {
  name: string;
  path: string;
  packages: number;
  exposure: Exposure;
  ecosystems: string[];
  warnings: string[];
}

/**
 * Remembered roots plus newly scanned ones. Nested roots are kept on purpose: scanning Companies sees werbosLLM as
 * one project, while scanning werbosLLM itself is what finds the projects inside it (beacon, glasshouse …).
 */
export function mergeRoots(remembered: string[], added: string[]): string[] {
  return [...new Set([...remembered, ...added])];
}

/** Scan every project under the given roots, save them, and forget projects that were deleted. */
export function scanRoots(db: DatabaseSync, roots: string[]): ScanSummary[] {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'ignored'").get() as { value: string } | undefined;
  setIgnored(JSON.parse(row?.value ?? "[]"));
  const out: ScanSummary[] = [];
  for (const root of roots) {
    for (const dir of findProjects(root)) {
      const s = scanProject(dir);
      saveProject(db, s);
      const packages = s.components.reduce((n, c) => n + c.packages.length, 0);
      if (!packages && !s.infra.length) continue;
      out.push({ name: s.name, path: s.path, packages, exposure: s.exposure, ecosystems: [...new Set(s.components.map((c) => c.ecosystem))], warnings: s.warnings });
    }
  }
  for (const { path } of db.prepare("SELECT path FROM projects").all() as { path: string }[]) {
    if (isIgnored(path) || (roots.some((r) => path === r || path.startsWith(r + "/")) && !existsSync(path))) {
      db.prepare("DELETE FROM projects WHERE path = ?").run(path);
    }
  }
  return out;
}

// ---------------------------------------------------------------- persistence

export function saveProject(db: DatabaseSync, scan: ProjectScan): void {
  tx(db, () => {
    db.prepare("DELETE FROM projects WHERE path = ?").run(scan.path);
    if (!scan.components.length && !scan.infra.length) return; // nothing to track

    const { lastInsertRowid: projectId } = db
      .prepare("INSERT INTO projects (name, path, exposure, scanned_at, license) VALUES (?, ?, ?, ?, ?)")
      .run(scan.name, scan.path, scan.exposure, new Date().toISOString(), scan.license);
    const insIssue = db.prepare("INSERT INTO scan_issues (project_id, category, severity, title, detail, source) VALUES (?, ?, ?, ?, ?, ?)");
    for (const i of scan.issues) insIssue.run(projectId, i.category, i.severity, i.title, i.detail ?? null, i.source);
    const markScript = db.prepare("UPDATE packages SET install_script = 1 WHERE id = ?");

    const upsertPkg = db.prepare(
      "INSERT INTO packages (ecosystem, name, version) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET name = name RETURNING id",
    );
    const insComp = db.prepare("INSERT INTO components (project_id, kind, path, ecosystem) VALUES (?, ?, ?, ?)");
    const insUse = db.prepare(
      "INSERT INTO uses (component_id, package_id, direct, scope) VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET direct = max(direct, excluded.direct)",
    );
    const insEdge = db.prepare("INSERT OR IGNORE INTO edges (component_id, parent_id, child_id) VALUES (?, ?, ?)");
    const insInfra = db.prepare("INSERT INTO infra (project_id, kind, value, source, warning) VALUES (?, ?, ?, ?, ?)");

    for (const c of scan.components) {
      const { lastInsertRowid: compId } = insComp.run(projectId, c.kind, c.path, c.ecosystem);
      const ids = new Map<string, number | bigint>();
      for (const p of c.packages) {
        const row = upsertPkg.get(p.ecosystem, p.name, p.version) as { id: number };
        ids.set(pkgKey(p.name, p.version), row.id);
        if (p.installScript) markScript.run(row.id);
        insUse.run(compId, row.id, p.direct ? 1 : 0, p.scope);
      }
      for (const e of c.edges) {
        const a = ids.get(e.parent);
        const b = ids.get(e.child);
        if (a !== undefined && b !== undefined && a !== b) insEdge.run(compId, a, b);
      }
    }
    for (const i of scan.infra) insInfra.run(projectId, i.kind, i.value, i.source, i.warning ?? null);
  });
}
