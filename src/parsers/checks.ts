// Scan-time checks that need no network: where packages come from, and how containers / CI are configured.
// Each returns ScanIssue[]; findings are grouped per file so one bad lockfile is one issue, not 400.

import { parse as parseYaml } from "yaml";
import type { ScanIssue } from "../types.ts";

const DEFAULT_NPM = new Set(["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"]);

type Sev = ScanIssue["severity"];
const issue = (category: ScanIssue["category"], severity: Sev, title: string, source: string, detail?: string): ScanIssue => ({
  category, severity, title, source, detail,
});

/** Groups items under one issue per (severity, title) with an example list. */
function grouped(category: ScanIssue["category"], source: string, items: { severity: Sev; title: string; what: string }[]): ScanIssue[] {
  const g = new Map<string, { severity: Sev; title: string; what: string[] }>();
  for (const i of items) {
    const k = i.severity + i.title;
    const e = g.get(k) ?? { severity: i.severity, title: i.title, what: [] };
    e.what.push(i.what);
    g.set(k, e);
  }
  return [...g.values()].map((e) =>
    issue(category, e.severity, `${e.title} (${e.what.length})`, source, e.what.slice(0, 8).join(", ") + (e.what.length > 8 ? ", …" : "")),
  );
}

// ---------------------------------------------------------------- package sources / dependency confusion

/** Scoped registries from .npmrc: "@acme" -> "npm.acme.internal" */
export function npmrcScopes(text: string): Map<string, string> {
  const m = new Map<string, string>();
  for (const line of text.split("\n")) {
    const s = line.trim().match(/^(@[\w.-]+):registry\s*=\s*(\S+)/);
    if (s) m.set(s[1], hostOf(s[2]) ?? s[2]);
  }
  return m;
}

const hostOf = (url: string) => url.match(/^[a-z+]+:\/\/(?:[^@/]+@)?([^/:]+)/i)?.[1]?.toLowerCase() ?? null;

function classifyNpmUrl(name: string, url: string, scopes: Map<string, string>) {
  const out: { severity: Sev; title: string; what: string }[] = [];
  const scope = name.startsWith("@") ? name.split("/")[0] : null;
  const privateHost = scope ? scopes.get(scope) : undefined;
  if (/^(git\+|git:|github:|gitlab:|bitbucket:)/.test(url) || /\.git(#|$)/.test(url)) {
    out.push({ severity: "MODERATE", title: "installed from git, not a registry (mutable, no integrity hash)", what: name });
  } else if (url.startsWith("http://")) {
    out.push({ severity: "HIGH", title: "downloaded over plain HTTP (can be tampered with in transit)", what: name });
  } else if (url.startsWith("https://")) {
    const host = hostOf(url)!;
    if (privateHost && host !== privateHost) {
      out.push({ severity: "HIGH", title: `dependency confusion: ${scope} is mapped to ${privateHost} but resolved from ${host}`, what: name });
    } else if (!DEFAULT_NPM.has(host) && host !== privateHost) {
      out.push({ severity: "MODERATE", title: `resolved from non-default registry ${host}`, what: name });
    }
  }
  return out;
}

export function checkPackageLock(text: string, source: string, scopes: Map<string, string>): ScanIssue[] {
  const lock = JSON.parse(text);
  const items: { severity: Sev; title: string; what: string }[] = [];
  for (const [key, e] of Object.entries<any>(lock.packages ?? {})) {
    if (!key.includes("node_modules/") || e.link) continue;
    const name = e.name ?? key.slice(key.lastIndexOf("node_modules/") + 13);
    if (typeof e.resolved === "string") {
      items.push(...classifyNpmUrl(name, e.resolved, scopes));
      if (e.resolved.startsWith("https://") && !e.integrity && !/\.git/.test(e.resolved)) {
        items.push({ severity: "LOW", title: "no integrity hash recorded", what: name });
      }
    }
  }
  return grouped("source", source, items);
}

export function checkPnpmLock(text: string, source: string, scopes: Map<string, string>): ScanIssue[] {
  const lock: any = parseYaml(text) ?? {};
  const items: { severity: Sev; title: string; what: string }[] = [];
  for (const [key, e] of Object.entries<any>(lock.packages ?? {})) {
    const name = key.replace(/^\//, "").replace(/\(.*$/, "").replace(/@[^@]*$/, "") || key;
    const r = e?.resolution ?? {};
    if (r.tarball) items.push(...classifyNpmUrl(name, String(r.tarball), scopes));
    if (r.repo || r.type === "git") items.push({ severity: "MODERATE", title: "installed from git, not a registry (mutable, no integrity hash)", what: name });
  }
  return grouped("source", source, items);
}

export function checkYarnLock(text: string, source: string, scopes: Map<string, string>): ScanIssue[] {
  const items: { severity: Sev; title: string; what: string }[] = [];
  let current = "";
  for (const raw of text.split("\n")) {
    if (raw && !raw.startsWith(" ") && !raw.startsWith("#")) {
      const first = raw.replace(/:$/, "").split(",")[0].trim().replace(/^"|"$/g, "");
      current = first.slice(0, first.indexOf("@", 1) > 0 ? first.indexOf("@", 1) : undefined);
    }
    const m = raw.match(/^\s+resolved:?\s+"?([^"\s]+)"?/);
    if (m && current) items.push(...classifyNpmUrl(current, m[1], scopes));
  }
  return grouped("source", source, items);
}

export function checkCargoLock(text: string, source: string): ScanIssue[] {
  const items: { severity: Sev; title: string; what: string }[] = [];
  let name = "";
  for (const line of text.split("\n")) {
    const n = line.match(/^name = "([^"]+)"/);
    if (n) name = n[1];
    const s = line.match(/^source = "([^"]+)"/);
    if (!s) continue;
    if (s[1].startsWith("git+")) items.push({ severity: "MODERATE", title: "crate pulled from git, not crates.io", what: name });
    else if (!/crates\.io-index|index\.crates\.io/.test(s[1])) items.push({ severity: "MODERATE", title: `crate from alternate registry ${hostOf(s[1].replace(/^(registry|sparse)\+/, "")) ?? s[1]}`, what: name });
  }
  return grouped("source", source, items);
}

export function checkRequirements(text: string, source: string): ScanIssue[] {
  const out: ScanIssue[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (/^--extra-index-url\b/.test(line)) {
      out.push(issue("source", "HIGH", "dependency confusion risk: --extra-index-url (pip takes the highest version from ANY index)", source,
        `${line.replace(/\/\/[^@/]+@/, "//***@")}. Use --index-url with a proxy that mirrors PyPI, or pin with hashes.`));
    } else if (/^(-i|--index-url)\b/.test(line) && line.includes("http://")) {
      out.push(issue("source", "HIGH", "package index over plain HTTP", source, line));
    } else if (/(^-e\s+)?git\+/.test(line)) {
      out.push(issue("source", "MODERATE", "package installed from git", source, line.split("#")[0]));
    }
  }
  return out;
}

export function checkPyLock(text: string, source: string): ScanIssue[] {
  const items: { severity: Sev; title: string; what: string }[] = [];
  let name = "";
  for (const line of text.split("\n")) {
    const n = line.match(/^name = "([^"]+)"/);
    if (n) name = n[1];
    const reg = line.match(/registry = "([^"]+)"/) ?? line.match(/^url = "([^"]+)"/);
    if (reg && !/pypi\.org|files\.pythonhosted\.org/.test(reg[1])) items.push({ severity: "MODERATE", title: `from non-PyPI index ${hostOf(reg[1]) ?? reg[1]}`, what: name });
    if (/git = "|type = "git"/.test(line)) items.push({ severity: "MODERATE", title: "package installed from git", what: name });
  }
  return grouped("source", source, items);
}

export function checkNugetConfig(text: string, source: string): ScanIssue[] {
  const sources = [...text.matchAll(/<add\s+key="[^"]*"\s+value="(https?:[^"]+)"/gi)].map((m) => m[1]);
  const out: ScanIssue[] = [];
  if (sources.length > 1 && !/<packageSourceMapping>/i.test(text)) {
    out.push(issue("source", "MODERATE", "multiple NuGet feeds without packageSourceMapping (dependency confusion risk)", source, sources.join(", ")));
  }
  for (const s of sources) if (s.startsWith("http://")) out.push(issue("source", "HIGH", "NuGet feed over plain HTTP", source, s));
  return out;
}

export function checkGoMod(text: string, source: string): ScanIssue[] {
  const reps = [...text.matchAll(/^\s*(?:replace\s+)?(\S+)(?:\s+\S+)?\s+=>\s+(\S+)/gm)].map((m) => `${m[1]} => ${m[2]}`);
  return reps.length ? [issue("source", "LOW", `go.mod replaces ${reps.length} module(s) (forks / local paths skip the checksum DB)`, source, reps.slice(0, 6).join(", "))] : [];
}

// ---------------------------------------------------------------- containers

const SECRETISH = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)/i;
const DB_PORTS: Record<string, string> = { "5432": "Postgres", "3306": "MySQL", "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch", "11211": "Memcached", "5984": "CouchDB", "8086": "InfluxDB" };

export function checkDockerfile(text: string, source: string): ScanIssue[] {
  const out: ScanIssue[] = [];
  const lines = text.split("\n").map((l) => l.trim());
  const lastFrom = lines.map((l, i) => (/^FROM\s/i.test(l) ? i : -1)).filter((i) => i >= 0).at(-1) ?? 0;
  const finalStage = lines.slice(lastFrom);
  const users = finalStage.filter((l) => /^USER\s/i.test(l));
  const fromImage = lines[lastFrom]?.split(/\s+/)[1] ?? "";
  if ((!users.length || /^USER\s+(root|0)(:|\s|$)/i.test(users.at(-1)!)) && !/distroless|nonroot|chainguard/.test(fromImage)) {
    out.push(issue("infra", "MODERATE", "container runs as root (no USER in final stage)", source, "Add a non-root USER so a compromised process can't own the container."));
  }
  for (const l of lines) {
    if (/(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(l)) out.push(issue("infra", "MODERATE", "pipes a downloaded script straight into a shell", source, l.slice(0, 160)));
    if (/^ADD\s+https?:\/\//i.test(l)) out.push(issue("infra", "LOW", "ADD from a URL (unverified download; prefer curl + checksum)", source, l.slice(0, 160)));
    const env = l.match(/^(ENV|ARG)\s+([A-Z0-9_]+)[=\s]+["']?([^"'\s$]{4,})/i);
    if (env && SECRETISH.test(env[2]) && !/^(changeme|example|xxx+|your[_-])/i.test(env[3])) {
      out.push(issue("infra", "HIGH", `secret baked into the image: ${env[1]} ${env[2]}`, source, "Anyone who pulls the image can read it. Pass it at runtime instead."));
    }
  }
  return out;
}

export function checkCompose(text: string, source: string): ScanIssue[] {
  const doc: any = parseYaml(text) ?? {};
  const out: ScanIssue[] = [];
  for (const [name, svc] of Object.entries<any>(doc.services ?? {})) {
    if (!svc || typeof svc !== "object") continue;
    if (svc.privileged === true) out.push(issue("infra", "HIGH", `${name}: privileged container (root on the host if compromised)`, source));
    if (svc.network_mode === "host") out.push(issue("infra", "MODERATE", `${name}: network_mode host (skips Docker network isolation)`, source));
    for (const v of svc.volumes ?? []) {
      const s = typeof v === "string" ? v : v?.source ?? "";
      if (String(s).includes("docker.sock")) out.push(issue("infra", "HIGH", `${name}: mounts docker.sock (full control of the Docker host)`, source));
    }
    for (const p of svc.ports ?? []) {
      const spec = typeof p === "object" ? `${p.host_ip ? p.host_ip + ":" : ""}${p.published ?? ""}:${p.target ?? ""}` : String(p);
      const parts = spec.split(":");
      const container = parts.at(-1)!.split("/")[0];
      const bound = parts.length === 3 ? parts[0] : "0.0.0.0";
      if (DB_PORTS[container] && !/^(127\.0\.0\.1|localhost|::1|\[::1\])$/.test(bound)) {
        // Production compose files are what face the internet; dev ones still expose the DB on café Wi-Fi.
        const prod = /prod|deploy|release/i.test(source);
        out.push(issue("infra", prod ? "HIGH" : "MODERATE", `${name}: ${DB_PORTS[container]} port ${container} published on all interfaces`, source, `Bind to 127.0.0.1 ("127.0.0.1:${parts.length >= 2 ? parts.at(-2) : container}:${container}") or drop the ports entry.`));
      }
    }
    const env = svc.environment;
    const pairs: [string, unknown][] = Array.isArray(env) ? env.map((e: string) => e.split("=") as [string, string]) : Object.entries(env ?? {});
    const literal = pairs.filter(([k, v]) => SECRETISH.test(k) && typeof v === "string" && v.length >= 3 && !v.includes("${"));
    if (literal.length) out.push(issue("infra", "MODERATE", `${name}: hardcoded secrets in compose file`, source, literal.map(([k]) => k).join(", ")));
  }
  return out;
}

// ---------------------------------------------------------------- GitHub Actions

const UNTRUSTED_CTX = /\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|head_commit\.(message|author\.(name|email))|commits\[[^\]]*\]\.message|pages\[[^\]]*\]\.page_name)|github\.head_ref)\s*\}\}/;

export function checkWorkflow(text: string, source: string): ScanIssue[] {
  let doc: any;
  try {
    doc = parseYaml(text);
  } catch {
    return [];
  }
  const out: ScanIssue[] = [];
  const on = doc?.on ?? doc?.[true as any]; // YAML 1.1 parses bare `on:` as boolean true
  const triggers = typeof on === "string" ? [on] : Array.isArray(on) ? on : Object.keys(on ?? {});
  if (triggers.includes("pull_request_target") && /github\.event\.pull_request\.head\.(sha|ref)|refs\/pull\//.test(text)) {
    out.push(issue("infra", "CRITICAL", "pull_request_target checks out PR code (\"pwn request\": forks can run code with your secrets)", source,
      "Use pull_request instead, or never check out / build the PR head in a pull_request_target job."));
  }
  if (doc?.permissions === "write-all") out.push(issue("infra", "MODERATE", "workflow token has write-all permissions", source));
  for (const [jobName, job] of Object.entries<any>(doc?.jobs ?? {})) {
    if (job?.permissions === "write-all") out.push(issue("infra", "MODERATE", `${jobName}: write-all token permissions`, source));
    for (const step of job?.steps ?? []) {
      if (typeof step?.run === "string" && UNTRUSTED_CTX.test(step.run)) {
        out.push(issue("infra", "HIGH", `${jobName}: script injection, untrusted event text interpolated into run:`, source,
          `${step.run.match(UNTRUSTED_CTX)![0]}. Pass it through env: and reference "$VAR" instead.`));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- project license

/** Best-effort SPDX id for the project itself (package.json, Cargo.toml, pyproject, LICENSE file). */
export function projectLicense(files: { packageJson?: string; cargoToml?: string; pyproject?: string; licenseText?: string }): string | null {
  try {
    const l = files.packageJson && JSON.parse(files.packageJson).license;
    if (typeof l === "string" && l !== "UNLICENSED") return l;
    if (l === "UNLICENSED") return "proprietary";
  } catch {}
  const toml = (files.cargoToml ?? "") + "\n" + (files.pyproject ?? "");
  const t = toml.match(/^license\s*=\s*"([^"]+)"/m)?.[1] ?? toml.match(/^license\s*=\s*\{\s*text\s*=\s*"([^"]+)"/m)?.[1];
  if (t) return t;
  const txt = (files.licenseText ?? "").slice(0, 3000);
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/i.test(txt)) return "AGPL-3.0";
  if (/GNU LESSER GENERAL PUBLIC/i.test(txt)) return "LGPL-3.0";
  if (/GNU GENERAL PUBLIC LICENSE/i.test(txt)) return /Version 2/i.test(txt) ? "GPL-2.0" : "GPL-3.0";
  if (/Apache License/i.test(txt)) return "Apache-2.0";
  if (/Mozilla Public License/i.test(txt)) return "MPL-2.0";
  if (/MIT License|Permission is hereby granted, free of charge/i.test(txt)) return "MIT";
  if (/BSD/i.test(txt) && /Redistribution and use/i.test(txt)) return "BSD-3-Clause";
  if (/ISC License/i.test(txt)) return "ISC";
  return null;
}
