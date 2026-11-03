// Infrastructure dependencies: the stuff Dependabot never sees.
// Base images, CI actions, where it's hosted, which domains point at it, how it ships.

import { parse as parseYaml } from "yaml";
import type { Infra } from "../types.ts";

const SHA = /^[0-9a-f]{40}$/;
const IGNORED_DOMAINS = /^(localhost|127\.|0\.0\.0\.0|github\.com|www\.w3\.org|schemas?\.)|(^|\.)(example\.(com|org|net)|localhost|test|invalid|local)$/;

export function cleanDomain(raw: string): string | null {
  const m = raw.trim().match(/^(?:https?:\/\/)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?(?:\/|$)/i);
  if (!m) return null;
  const d = m[1].toLowerCase();
  return IGNORED_DOMAINS.test(d) ? null : d;
}

// ---------------------------------------------------------------- Docker

export function parseDockerfile(text: string, source: string): Infra[] {
  const out: Infra[] = [];
  const stages = new Set<string>();
  for (const raw of text.split("\n")) {
    const m = raw.trim().match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
    if (!m) continue;
    const image = m[1];
    if (m[2]) stages.add(m[2].toLowerCase());
    if (image === "scratch" || stages.has(image.toLowerCase()) || image.includes("${") || image.includes("$")) continue;
    out.push({ kind: "docker-image", value: image, source, warning: imageWarning(image) });
  }
  return out;
}

function imageWarning(image: string): string | undefined {
  if (image.includes("@sha256:")) return undefined;
  const tag = image.split("/").pop()!.split(":")[1];
  if (!tag) return "no tag (implicit :latest)";
  if (tag === "latest") return "uses :latest";
  return undefined; // pinned to a tag: fine for v1
}

export function parseCompose(text: string, source: string): Infra[] {
  const doc: any = parseYaml(text) ?? {};
  const out: Infra[] = [];
  for (const svc of Object.values<any>(doc.services ?? {})) {
    if (typeof svc?.image === "string" && !svc.image.includes("$")) {
      out.push({ kind: "docker-image", value: svc.image, source, warning: imageWarning(svc.image) });
    }
  }
  out.push({ kind: "host", value: "self-hosted (docker compose)", source });
  return out;
}

// ---------------------------------------------------------------- GitHub Actions

export function parseWorkflow(text: string, source: string): Infra[] {
  let doc: any;
  try {
    doc = parseYaml(text);
  } catch {
    return [];
  }
  const out: Infra[] = [];
  const uses: string[] = [];
  for (const job of Object.values<any>(doc?.jobs ?? {})) {
    if (typeof job?.uses === "string") uses.push(job.uses); // reusable workflow
    for (const step of job?.steps ?? []) if (typeof step?.uses === "string") uses.push(step.uses);
  }
  for (const u of uses) {
    if (u.startsWith("./") || u.startsWith("docker://")) continue;
    const [name, ref = ""] = u.split("@");
    const warning = SHA.test(ref) ? undefined : ref ? `mutable ref @${ref} (pin to a commit SHA)` : "no ref";
    out.push({ kind: "gh-action", value: `${name}@${ref}`, source, warning });
    if (/actions\/deploy-pages|peaceiris\/actions-gh-pages|JamesIves\/github-pages-deploy-action/.test(name)) {
      out.push({ kind: "host", value: "github-pages", source });
    }
  }
  return out;
}

// ---------------------------------------------------------------- hosts, domains, distribution

/**
 * Called with each interesting filename found in a project. Returns the infra it implies.
 * `rel` is the path relative to the project root; `text` is the file contents.
 */
export function detectFromFile(base: string, rel: string, text: string): Infra[] {
  const out: Infra[] = [];
  const host = (value: string) => out.push({ kind: "host", value, source: rel });
  const domain = (raw: string | undefined) => {
    const d = raw && cleanDomain(raw);
    if (d) out.push({ kind: "domain", value: d, source: rel });
  };
  const dist = (value: string) => out.push({ kind: "distribution", value, source: rel });

  switch (base) {
    case "vercel.json": {
      host("vercel");
      try {
        const j = JSON.parse(text);
        for (const a of [].concat(j.alias ?? [])) domain(a);
      } catch {}
      break;
    }
    case "project.json":
      if (rel.includes(".vercel/")) host("vercel");
      break;
    case "netlify.toml":
      host("netlify");
      break;
    case "fly.toml": {
      host("fly.io");
      const app = text.match(/^app\s*=\s*["']([^"']+)["']/m)?.[1];
      if (app) domain(`${app}.fly.dev`);
      break;
    }
    case "wrangler.toml":
    case "wrangler.json":
    case "wrangler.jsonc": {
      host("cloudflare");
      for (const m of text.matchAll(/pattern\s*[=:]\s*["']([^"'*]+)/g)) domain(m[1]);
      break;
    }
    case "firebase.json":
      host("firebase");
      break;
    case "render.yaml":
      host("render");
      break;
    case "railway.json":
    case "railway.toml":
      host("railway");
      break;
    case "Procfile":
      host("heroku-style (Procfile)");
      break;
    case "CNAME": {
      const line = text.split("\n")[0];
      if (cleanDomain(line)) {
        host("github-pages");
        domain(line);
      }
      break;
    }
    case "Caddyfile": {
      host("self-hosted (caddy)");
      for (const m of text.matchAll(/^([a-z0-9][a-z0-9.,\s-]*\.[a-z]{2,})\s*\{/gim)) {
        for (const d of m[1].split(/[,\s]+/)) domain(d);
      }
      break;
    }
    case "package.json": {
      try {
        const j = JSON.parse(text);
        if (typeof j.homepage === "string" && /^https?:/.test(j.homepage)) {
          domain(j.homepage);
          if (j.homepage.includes("github.io")) host("github-pages");
        }
      } catch {}
      break;
    }
    case "app.json":
      if (/"expo"\s*:/.test(text)) dist("expo (iOS/Android app)");
      break;
    case "eas.json":
      dist("expo (iOS/Android app)");
      break;
    case "tauri.conf.json":
      dist("tauri (desktop app)");
      break;
    case "project.godot":
      dist("godot (game)");
      break;
    case "build.gradle":
    case "build.gradle.kts": {
      const id = text.match(/applicationId\s*=?\s*["']([^"']+)["']/)?.[1];
      if (id) dist(`android app (${id})`);
      break;
    }
    default:
      if (/^capacitor\.config\./.test(base)) dist("capacitor (mobile app)");
      // Static-site generators that declare their public URL.
      if (/^astro\.config\./.test(base)) domain(text.match(/site\s*:\s*["']([^"']+)["']/)?.[1]);
      if (/^(hugo|config)\.(toml|ya?ml)$/.test(base)) domain(text.match(/baseURL\s*[=:]\s*["']([^"']+)["']/i)?.[1]);
      if (base === "manifest.json" && /"manifest_version"/.test(text)) dist("browser extension");
  }
  return out;
}

/** Reads the origin URL from .git/config without shelling out. */
export function gitRemote(configText: string): string | null {
  const block = configText.split(/^\[/m).find((b) => b.startsWith('remote "origin"'));
  const url = block?.match(/url\s*=\s*(\S+)/)?.[1];
  if (!url) return null;
  return url.replace(/^git@github\.com:/, "github.com/").replace(/^https?:\/\//, "").replace(/\.git$/, "");
}
