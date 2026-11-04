// `mycelium serve`: the dashboard. Sign in → overview → Check (read-only) → Fix (branch → build/test → push → PR).
//
// Listens on 127.0.0.1 unless sign-in is configured. Every API call needs a per-install token that only the served
// page knows, and the Host header must match, so other websites can't drive it (CSRF / DNS rebinding).
// Fixes run as a child process: package managers block for minutes, and the page has to keep showing progress.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { DatabaseSync } from "node:sqlite";
import { createAuth } from "./auth.ts";
import { auditView, clearPrCache, findingsView, infraView, overview, PIPELINE, projectDetail, stepOf, withDowngradeHints, type Step } from "./dashboard.ts";
import { checkAll } from "./osv.ts";
import { saveProject, scanProject, scanRoots, setIgnored } from "./scan.ts";
import { enrich } from "./depsdev.ts";
import { pullProject, syncPrs } from "./prs.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(HERE, "..", "public");
const CLI = join(HERE, "cli.ts");
const STATIC: Record<string, string> = { "/style.css": "text/css", "/app.js": "text/javascript", "/favicon.svg": "image/svg+xml" };
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

interface Job {
  id: number;
  project: string;
  state: "running" | "done" | "failed";
  reached: Step[];
  lines: string[];
  result: any;
  error: string | null;
  startedAt: string;
}

function loadConfig() {
  const file = join(homedir(), ".mycelium", "config.json");
  const cfg = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
  const e = process.env;
  if (e.GATEKEEP_ISSUER) cfg.auth = { issuer: e.GATEKEEP_ISSUER, clientId: e.GATEKEEP_CLIENT_ID || "mycelium", allowedEmails: (e.GATEKEEP_ALLOWED_EMAILS || "").split(",").map((s) => s.trim()).filter(Boolean) };
  return { auth: cfg.auth ?? null, baseUrl: (e.MYCELIUM_BASE_URL ?? cfg.baseUrl ?? null) as string | null, host: (e.MYCELIUM_HOST ?? cfg.host ?? "127.0.0.1") as string };
}

export function serve(db: DatabaseSync, port: number) {
  // Stable across restarts (open tabs keep working); only pages served by this machine ever see it.
  let token = (db.prepare("SELECT value FROM settings WHERE key = 'serve_token'").get() as { value: string } | undefined)?.value;
  if (!token) {
    token = randomBytes(24).toString("hex");
    db.prepare("INSERT INTO settings (key, value) VALUES ('serve_token', ?)").run(token);
  }
  const setting = (k: string) => (db.prepare("SELECT value FROM settings WHERE key = ?").get(k) as { value: string } | undefined)?.value;

  const cfg = loadConfig();
  const local = cfg.host === "127.0.0.1" || cfg.host === "localhost";
  const baseUrl = cfg.baseUrl ?? `http://mycelium.localhost:${port}`;
  // A loopback bind behind a tunnel or `tailscale serve` is still reachable from elsewhere, so the public URL counts too.
  const localUrl = /^http:\/\/([\w.-]*\.)?(localhost|127\.0\.0\.1)(:\d+)?\/?$/.test(baseUrl);
  if (!cfg.auth && (!local || !localUrl)) throw new Error(`Refusing to serve ${local ? baseUrl : cfg.host} without sign-in: anyone who can reach it could run fixes. Configure auth in ~/.mycelium/config.json.`);
  const auth = cfg.auth ? createAuth(cfg.auth, baseUrl, join(homedir(), ".mycelium")) : null;
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `mycelium.localhost:${port}`, new URL(baseUrl).host]);

  let busy: string | null = null; // one job at a time: they run package managers and git
  let job: Job | null = null;
  let jobCount = 0;

  const page = (file: string, res: ServerResponse) => {
    const html = readFileSync(join(PUBLIC, file), "utf8").replace("__TOKEN__", token!);
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" });
    res.end(html);
  };

  function startFix(body: any): Job {
    const args = ["--experimental-strip-types", "--no-warnings=ExperimentalWarning", CLI, "fix", body.project, "--apply", "--stream"];
    if (body.verify !== false) args.push("--verify");
    if (body.pr) args.push("--pr");
    if (body.allowMajor) args.push("--major");
    if (Array.isArray(body.only) && body.only.length) args.push("--only", body.only.join(","));
    const current: Job = { id: ++jobCount, project: body.project, state: "running", reached: [], lines: [], result: null, error: null, startedAt: new Date().toISOString() };
    job = current;
    busy = `fixing ${body.project}`;
    const child = spawn(process.execPath, args, { env: { ...process.env, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    let buf = "", errors = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
      buf += chunk;
      const parts = buf.split("\n");
      buf = parts.pop() ?? "";
      for (const line of parts) {
        if (line.startsWith("@result ")) {
          try {
            current.result = JSON.parse(line.slice(8));
          } catch { /* reported below as no result */ }
        } else if (line.startsWith("@log ")) {
          const text = line.slice(5);
          current.lines.push(text);
          const step = stepOf(text);
          if (step && !current.reached.includes(step)) current.reached.push(step);
        }
      }
    });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (errors = (errors + chunk).slice(-4000)));
    child.on("error", (e) => {
      current.state = "failed";
      current.error = e.message;
      busy = null;
    });
    child.on("close", (code) => {
      if (code === 0 && current.result) current.state = "done";
      else {
        current.state = "failed";
        current.error = errors.trim() || `the fix process exited with code ${code}`;
      }
      busy = null;
      clearPrCache();
    });
    return current;
  }

  const server = createServer(async (req, res) => {
    const host = req.headers.host ?? "";
    if (!hosts.has(host)) return send(res, 403, { error: "bad host" });
    const url = new URL(req.url ?? "/", baseUrl);
    const p = url.pathname;

    try {
      if (req.method === "GET" && STATIC[p]) {
        res.writeHead(200, { "content-type": STATIC[p] + "; charset=utf-8", "cache-control": "no-cache", "x-content-type-options": "nosniff" });
        return res.end(readFileSync(join(PUBLIC, p.slice(1))));
      }
      if (auth) {
        if (p === "/auth/login") return await auth.login(req, res);
        if (p === "/auth/callback") return await auth.callback(req, res);
        if (p === "/auth/logout") return await auth.logout(req, res);
      }
      const user = auth ? auth.user(req) : null;
      if (auth && !user) {
        if (req.method === "GET" && p === "/login") return page("login.html", res);
        if (req.method === "GET" && p === "/") return void res.writeHead(302, { Location: "/login" }).end();
        return send(res, 401, { error: "sign in first" });
      }
      if (req.method === "GET" && (p === "/" || p === "/login")) {
        if (p === "/login") return void res.writeHead(302, { Location: "/" }).end();
        return page("index.html", res);
      }
      if (!p.startsWith("/api/")) return send(res, 404, { error: "not found" });
      if (req.headers["x-mycelium-token"] !== token) return send(res, 403, { error: "bad token" });

      if (req.method === "GET") {
        if (p === "/api/overview") return send(res, 200, { ...overview(db), user: user?.email ?? null, signIn: !!auth, busy, job: job && summary(job) });
        if (p === "/api/project") return send(res, 200, projectDetail(db, url.searchParams.get("name") ?? ""));
        if (p === "/api/findings") return send(res, 200, findingsView(db));
        if (p === "/api/audit") return send(res, 200, auditView(db));
        if (p === "/api/infra") return send(res, 200, infraView(db));
        if (p === "/api/job") return send(res, 200, job ? { ...summary(job), lines: job.lines, result: job.result, error: job.error } : null);
        return send(res, 404, { error: "not found" });
      }
      if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });
      const body = await readBody(req);
      if (["/api/check", "/api/fix", "/api/pull"].includes(p) && typeof body.project !== "string") return send(res, 400, { error: "which project? (missing project name)" });
      if (busy) return send(res, 409, { error: `Mycelium is busy (${busy}). Try again when that finishes.` });
      const pathOf = (name: string) => (db.prepare("SELECT path FROM projects WHERE name = ?").get(name) as { path: string } | undefined)?.path;

      if (p === "/api/fix") {
        if (!pathOf(body.project)) return send(res, 400, { error: "unknown project" });
        return send(res, 202, summary(startFix(body)));
      }

      const run = async (label: string, work: () => Promise<unknown>) => {
        busy = label;
        try {
          const out = await work();
          clearPrCache();
          return send(res, 200, out);
        } finally {
          busy = null;
        }
      };
      setIgnored(JSON.parse(setting("ignored") ?? "[]"));
      // Check is read-only for the repo: it re-reads the lockfiles and asks OSV. Only Mycelium's own database changes.
      if (p === "/api/check") {
        const path = pathOf(body.project);
        if (!path) return send(res, 400, { error: "unknown project" });
        return await run(`checking ${body.project}`, async () => {
          saveProject(db, scanProject(path));
          await checkAll(db);
          return withDowngradeHints(projectDetail(db, body.project));
        });
      }
      if (p === "/api/pull") {
        const path = pathOf(body.project);
        if (!path) return send(res, 400, { error: "unknown project" });
        return await run(`pulling ${body.project}`, async () => {
          const r = pullProject(db, path);
          if (r.pulled.length) {
            await checkAll(db);
            await syncPrs(db);
          }
          return r;
        });
      }
      if (p === "/api/refresh") {
        return await run("rescanning everything", async () => {
          scanRoots(db, JSON.parse(setting("roots") ?? "[]"));
          await checkAll(db);
          await enrich(db);
          await syncPrs(db);
          return { ok: true };
        });
      }
      send(res, 404, { error: "not found" });
    } catch (e) {
      send(res, 400, { error: (e as Error).message });
    }
  });

  server.listen(port, cfg.host, () => {
    setImmediate(() => overview(db)); // warm the slow part, so the first page load is quick
    console.log(`🍄 Mycelium at ${baseUrl}/  ${auth ? "(sign-in on)" : "(this computer only)"}  (Ctrl-C to stop)`);
    if (process.platform === "darwin" && localUrl && !process.env.MYCELIUM_NO_OPEN) execFile("open", [baseUrl + "/"]);
  });
}

const summary = (j: Job) => ({ id: j.id, project: j.project, state: j.state, reached: j.reached, pipeline: PIPELINE, startedAt: j.startedAt });

function send(res: ServerResponse, status: number, data: unknown) {
  if (res.headersSent) return void res.end(); // never crash the server over a late error
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(data));
}

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (ch) => {
      raw += ch;
      if (raw.length > 1e6) reject(new Error("body too large"));
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("invalid JSON"));
      }
    });
  });
}
