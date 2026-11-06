// `mycelium serve`: the dashboard. Sign in → overview → Check (read-only) → Fix (branch → build/test → push → PR).
//
// Listens on 127.0.0.1 unless sign-in is configured. Every API call needs a per-install token that only the served
// page knows, and the Host header must match, so other websites can't drive it (CSRF / DNS rebinding).
// Fixes run as a child process: package managers block for minutes, and the page has to keep showing progress.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { DatabaseSync } from "node:sqlite";
import { createAuth } from "./auth.ts";
import { auditView, clearPrCache, findingsView, fixedView, infraView, overview, PIPELINE, projectDetail, stepOf, withDowngradeHints, type Step } from "./dashboard.ts";
import { checkAll } from "./osv.ts";
import { withoutServiceKeys } from "./net.ts";
import { saveProject, scanProject, scanRoots, setIgnored } from "./scan.ts";
import { enrich } from "./depsdev.ts";
import { pullProject, syncPrs } from "./prs.ts";
import { alertsView, loadAlertSettings, runAlerts, saveAlertSettings, sendTestEmail } from "./alerts.ts";
import { agentOnFor, applyRepoChange, cleanError, loadRepoChoices, repoChoicesView, saveRepoChoices, fetchRepos, listGithubRepos, loadAutoWatch, loadHiddenAccounts, loadRepoIssues, parseRepoInput, saveAutoWatch, saveHiddenAccounts, updateRepoIssues, validSlug, type GithubRepo } from "./repos.ts";
import { companyName, saveCompanyName } from "./db.ts";
import { cloneDirs, readRepoList } from "./sync.ts";
import Anthropic from "@anthropic-ai/sdk";
import { agentsView, pollAgents, saveAgentSettings } from "./agents.ts";
import { apiEngine, claudeCodeEngine, detectEngine, EngineTrouble, githubPort, loadReviewSettings, pollReviews, requeueReview, resetInterrupted, reviewsView, saveReviewSettings, type EngineKind, type ReviewClient } from "./review.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(HERE, "..", "public");
const CLI = join(HERE, "cli.ts");
const STATIC: Record<string, string> = { "/style.css": "text/css", "/app.js": "text/javascript", "/favicon.svg": "image/svg+xml" };
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const LOCAL_ONLY = "This install scans folders on this computer, so there's no repo list to change.";

/** Importing or re-scanning a few repos, in the background. Only ever touches those repos, not the whole account. */
interface RepoJob {
  kind: "import" | "scan";
  state: "running" | "done" | "failed";
  step: "fetching" | "scanning" | "checking" | "finished";
  total: number;
  finished: number;
  current: string[];
  failed: { slug: string; error: string }[];
  warnings: string[];
  error: string | null;
  startedAt: string;
}

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
  const repos = e.MYCELIUM_REPOS_DIR && e.MYCELIUM_REPOS_LIST ? { dir: e.MYCELIUM_REPOS_DIR, list: e.MYCELIUM_REPOS_LIST } : null;
  return { repos, auth: cfg.auth ?? null, baseUrl: (e.MYCELIUM_BASE_URL ?? cfg.baseUrl ?? null) as string | null, host: (e.MYCELIUM_HOST ?? cfg.host ?? "127.0.0.1") as string };
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

  // Listing repos walks GitHub's pages: seconds on a big account, and it rarely changes while someone's ticking boxes.
  let githubCache: { at: number; repos: GithubRepo[] } | null = null;
  const githubRepos = async (fresh = false) => {
    if (fresh || !githubCache || Date.now() - githubCache.at > 5 * 60_000) githubCache = { at: Date.now(), repos: await listGithubRepos() };
    return githubCache.repos;
  };

  const watchedList = () => (cfg.repos && existsSync(cfg.repos.list) ? readRepoList(cfg.repos.list) : []);

  // Identity of the GitHub login Mycelium acts as. Cached with the repo list: it's a network call, and rarely changes.
  let githubUserCache: { at: number; value: { login: string; name: string | null } | null; error: string | null } | null = null;
  const githubUser = async () => {
    if (!githubUserCache || Date.now() - githubUserCache.at > 5 * 60_000) {
      try {
        const { stdout } = await promisify(execFile)("gh", ["api", "user", "--jq", "{login, name}"], { encoding: "utf8", timeout: 20_000 });
        githubUserCache = { at: Date.now(), value: JSON.parse(stdout), error: null };
      } catch (e) {
        console.error("reading the GitHub user:", e);
        githubUserCache = { at: Date.now(), value: null, error: "not connected" };
      }
    }
    return githubUserCache;
  };

  let repoJob: RepoJob | null = null;
  function startRepoJob(kind: RepoJob["kind"], slugs: string[]): RepoJob {
    const current: RepoJob = { kind, state: "running", step: "fetching", total: slugs.length, finished: 0, current: [], failed: [], warnings: [], error: null, startedAt: new Date().toISOString() };
    repoJob = current;
    busy = `${kind === "import" ? "importing" : "scanning"} ${slugs.length} repo${slugs.length === 1 ? "" : "s"}`;
    void (async () => {
      try {
        const { failed, pathOf } = await fetchRepos(cfg.repos!.dir, watchedList(), slugs, (u) => {
          if (u.state === "start") current.current.push(u.slug);
          else {
            current.current = current.current.filter((s) => s !== u.slug);
            current.finished++;
          }
        });
        current.failed = failed;
        const failedNames = new Set(failed.map((f) => f.slug));
        updateRepoIssues(db, slugs.filter((s) => !failedNames.has(s)), failed);
        current.step = "scanning";
        setIgnored(JSON.parse(setting("ignored") ?? "[]"));
        for (const slug of slugs) if (existsSync(pathOf(slug))) saveProject(db, scanProject(pathOf(slug))); // a failed pull still has last night's clone
        current.step = "checking";
        await checkAll(db); // fatal on failure: acting on a partial answer would clear findings that still apply
        try { await enrich(db); } catch (e) { current.warnings.push(`License and version data not updated: ${(e as Error).message}`); }
        try { await syncPrs(db); } catch (e) { current.warnings.push(`Fix history not updated: ${cleanError(e)}`); }
        const alert = await runAlerts(db, baseUrl);
        if (alert.error) current.warnings.push(`Couldn't send the alert email: ${alert.error}`);
        current.state = "done";
      } catch (e) {
        console.error("repo job failed:", e);
        current.state = "failed";
        current.error = (e as Error).message;
      } finally {
        current.step = "finished";
        current.current = [];
        busy = null;
        clearPrCache();
      }
    })();
    return current;
  }

  /** Update the clones, scan, check, sync PRs, send any alert. What Rescan does, and what follows a change to the repo list. */
  const rescanAll = async () => {
    const warnings: string[] = [];
    // Server clones exist only for Mycelium, so Rescan brings them up to date. Otherwise a merged PR looks
    // unmerged until the nightly sync. On a laptop these are your working folders: those are never pulled here.
    if (cfg.repos) {
      try {
        await promisify(execFile)(process.execPath, ["--experimental-strip-types", "--no-warnings=ExperimentalWarning", CLI, "sync", cfg.repos.dir, "--list", cfg.repos.list, "--pull-only"], { timeout: 15 * 60_000, maxBuffer: 1 << 24 });
      } catch (e: any) {
        const failed = String(e.stdout ?? "").split("\n").filter((l) => l.includes("✗"));
        console.error("repo sync:", failed.join("\n") || e.message);
        warnings.push(failed.length ? `${failed.length} repo(s) couldn't be updated and were scanned as they were.` : "Repos couldn't be updated, so they were scanned as they were.");
      }
    }
    scanRoots(db, JSON.parse(setting("roots") ?? "[]"));
    await checkAll(db); // fatal on failure: acting on a partial answer would clear findings that still apply
    // License and latest-version data is extra. Findings are saved by now, so losing it shouldn't fail the rescan.
    try { await enrich(db); } catch (e) { warnings.push(`License and version data not updated: ${(e as Error).message}`); }
    await syncPrs(db);
    const alert = await runAlerts(db, baseUrl);
    if (alert.error) warnings.push(`Couldn't send the alert email: ${alert.error}`);
    return { ok: true, warnings };
  };

  // PR reviews: polling, so GitHub never needs a way in to this machine. Doesn't take `busy`: it only reads git objects,
  // so it can run beside a fix or a rescan. One poll at a time.
  const reviewPoll: { running: boolean; lastPollAt: string | null; lastError: string | null } = { running: false, lastPollAt: null, lastError: null };
  // Asking Claude Code about its login takes a moment and rarely changes.
  let engineCache: { at: number; kind: EngineKind | null } | null = null;
  const reviewEngine = async () => {
    if (!engineCache || Date.now() - engineCache.at > 60_000) engineCache = { at: Date.now(), kind: await detectEngine() };
    return engineCache.kind;
  };
  const reviewRepoPath = (slug: string) => {
    if (!cfg.repos) return null;
    const folder = cloneDirs(watchedList()).get(slug);
    const path = folder && join(cfg.repos.dir, folder);
    return path && existsSync(join(path, ".git")) ? path : null;
  };
  const agentPoll: { running: boolean; lastError: string | null } = { running: false, lastError: null };
  const pollAgentsNow = async () => {
    if (agentPoll.running || !cfg.repos) return;
    agentPoll.running = true;
    try {
      await pollAgents(db, watchedList(), { github: githubPort, repoPath: reviewRepoPath, baseUrl, log: (s) => console.error(s), only: "rules" });
      agentPoll.lastError = null;
    } catch (e) {
      console.error("PR agents:", e);
      agentPoll.lastError = cleanError(e);
    } finally {
      agentPoll.running = false;
    }
  };
  // The AI lenses (Crimson, a11y) poll on their own flag: a slow review must never hold up the key watcher or Fungi.
  const lensPoll: { running: boolean; lastError: string | null } = { running: false, lastError: null };
  let lensesPausedUntil = 0;
  const pollLensesNow = async () => {
    if (lensPoll.running || !cfg.repos || Date.now() < lensesPausedUntil) return;
    lensPoll.running = true;
    try {
      const kind = await reviewEngine();
      const engine = kind === "api" ? apiEngine(new Anthropic() as unknown as ReviewClient) : kind === "claude-code" ? claudeCodeEngine : undefined;
      if (!engine) return;
      await pollAgents(db, watchedList(), { github: githubPort, repoPath: reviewRepoPath, baseUrl, log: (s) => console.error(s), engine, only: "ai" });
      lensPoll.lastError = null;
    } catch (e) {
      console.error("AI review agents:", e);
      lensPoll.lastError = cleanError(e);
      if (e instanceof EngineTrouble) lensesPausedUntil = Date.now() + 15 * 60_000;
    } finally {
      lensPoll.running = false;
    }
  };
  let reviewsPausedUntil = 0; // after a plan limit or an outage, there's no point asking again every two minutes
  const pollReviewsNow = async (manual = false) => {
    if (reviewPoll.running || !cfg.repos || !loadReviewSettings(db).enabled || (!manual && Date.now() < reviewsPausedUntil)) return;
    reviewPoll.running = true;
    try {
      const kind = await reviewEngine();
      if (!kind) return;
      await pollReviews(db, watchedList(), { github: githubPort, engine: kind === "api" ? apiEngine(new Anthropic() as unknown as ReviewClient) : claudeCodeEngine, repoPath: reviewRepoPath, baseUrl, log: (s) => console.error(s) });
      reviewPoll.lastError = null;
    } catch (e) {
      console.error("reviewing PRs:", e);
      reviewPoll.lastError = cleanError(e);
      if (e instanceof EngineTrouble) reviewsPausedUntil = Date.now() + 15 * 60_000;
    } finally {
      reviewPoll.running = false;
      reviewPoll.lastPollAt = new Date().toISOString();
    }
  };
  const reviewView = async () => ({ ...reviewsView(db, { managed: !!cfg.repos, engine: await reviewEngine(), lastError: reviewPoll.lastError ?? agentPoll.lastError, lastPollAt: reviewPoll.lastPollAt }), agents: agentsView(db), repoChoices: repoChoicesView(db, watchedList()) });

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
    const child = spawn(process.execPath, args, { env: { ...withoutServiceKeys(), NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
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
        if (p === "/api/overview") return send(res, 200, { ...overview(db), user: user?.email ?? null, signIn: !!auth, company: companyName(db), busy, job: job && summary(job) });
        if (p === "/api/project") return send(res, 200, projectDetail(db, url.searchParams.get("name") ?? ""));
        if (p === "/api/findings") return send(res, 200, findingsView(db));
        if (p === "/api/fixed") return send(res, 200, fixedView(db));
        if (p === "/api/audit") return send(res, 200, auditView(db));
        if (p === "/api/infra") return send(res, 200, infraView(db));
        if (p === "/api/alerts") return send(res, 200, alertsView(db));
        if (p === "/api/reviews") return send(res, 200, await reviewView());
        if (p === "/api/repos") {
          if (!cfg.repos) return send(res, 200, { managed: false, roots: JSON.parse(setting("roots") ?? "[]") });
          const list = watchedList();
          const folders = cloneDirs(list);
          const projectAt = new Map((db.prepare("SELECT name, path FROM projects").all() as { name: string; path: string }[]).map((r) => [r.path, r.name]));
          const watched = list.map((slug) => ({ slug, project: projectAt.get(join(cfg.repos!.dir, folders.get(slug)!)) ?? null }));
          let available: GithubRepo[] = [], error: string | null = null;
          try {
            available = await githubRepos(url.searchParams.has("fresh"));
          } catch (e) {
            console.error("listing GitHub repos:", e);
            error = "Couldn't list your GitHub repos. Check that `gh auth status` works on this server.";
          }
          return send(res, 200, { managed: true, watched, available, autoOwners: loadAutoWatch(db).owners, hiddenAccounts: loadHiddenAccounts(db), issues: loadRepoIssues(db), error });
        }
        if (p === "/api/repos/job") return send(res, 200, repoJob);
        if (p === "/api/profile") {
          const github = await githubUser();
          let accounts: { owner: string; repos: number }[] = [];
          try {
            const tally = new Map<string, number>();
            const hidden = new Set(loadHiddenAccounts(db));
            for (const r of (await githubRepos()).filter((x) => !hidden.has(x.owner))) tally.set(r.owner, (tally.get(r.owner) ?? 0) + 1);
            accounts = [...tally].map(([owner, repos]) => ({ owner, repos })).sort((a, b) => b.repos - a.repos || a.owner.localeCompare(b.owner));
          } catch { /* shown as not connected */ }
          const alerts = loadAlertSettings(db);
          return send(res, 200, {
            user: user?.email ?? null, signIn: !!auth, allowedEmails: cfg.auth?.allowedEmails ?? [], company: companyName(db),
            github: { login: github.value?.login ?? null, name: github.value?.name ?? null, accounts },
            install: { managed: !!cfg.repos, baseUrl, watched: watchedList().length, projects: (db.prepare("SELECT count(*) AS n FROM projects").get() as { n: number }).n },
            alerts: { enabled: alerts.enabled, recipients: alerts.recipients },
          });
        }
        if (p === "/api/job") return send(res, 200, job ? { ...summary(job), lines: job.lines, result: job.result, error: job.error } : null);
        return send(res, 404, { error: "not found" });
      }
      if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });
      const body = await readBody(req);
      // Settings, not work: fine while a rescan runs.
      if (p === "/api/profile") return send(res, 200, { company: saveCompanyName(db, body.company) });
      if (p === "/api/repos/hidden") return send(res, 200, { hiddenAccounts: saveHiddenAccounts(db, body.accounts), autoOwners: loadAutoWatch(db).owners });
      if (p === "/api/repos/parse") {
        const { slugs, invalid } = parseRepoInput(body.text);
        const watched = new Set(watchedList());
        const visible = new Set((await githubRepos()).map((r) => r.slug));
        return send(res, 200, {
          add: slugs.filter((s) => visible.has(s) && !watched.has(s)),
          already: slugs.filter((s) => watched.has(s)),
          notVisible: slugs.filter((s) => !visible.has(s) && !watched.has(s)),
          invalid,
        });
      }
      if (p === "/api/alerts") return send(res, 200, { ...saveAlertSettings(db, body), view: alertsView(db) });
      if (p === "/api/alerts/test") {
        await sendTestEmail(db, baseUrl, Array.isArray(body.recipients) ? body.recipients.map(String).filter(Boolean) : []);
        return send(res, 200, { ok: true });
      }
      if (p === "/api/reviews") {
        saveReviewSettings(db, body);
        void pollReviewsNow(true);
        return send(res, 200, await reviewView());
      }
      if (p === "/api/agents") {
        saveAgentSettings(db, body);
        void pollAgentsNow();
        void pollLensesNow();
        return send(res, 200, await reviewView());
      }
      if (p === "/api/agents/repos") {
        saveRepoChoices(db, body, watchedList());
        void pollAgentsNow();
        void pollLensesNow();
        void pollReviewsNow(true);
        return send(res, 200, await reviewView());
      }
      if (p === "/api/reviews/again") {
        if (!validSlug(body.repo) || !Number.isInteger(body.number)) return send(res, 400, { error: "Which PR?" });
        if (!agentOnFor(loadRepoChoices(db), body.repo, "review")) return send(res, 400, { error: `The reviewer is off for ${body.repo}. Tick it under Which repos first.` });
        requeueReview(db, body.repo, body.number);
        void pollReviewsNow(true);
        return send(res, 200, await reviewView());
      }
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
      if (p === "/api/refresh") return await run("rescanning everything", rescanAll);
      if (p === "/api/repos") {
        if (!cfg.repos) return send(res, 400, { error: LOCAL_ONLY });
        const add = Array.isArray(body.add) ? body.add : [], remove = Array.isArray(body.remove) ? body.remove : [];
        if (![...add, ...remove].every(validSlug)) return send(res, 400, { error: "That doesn't look like a GitHub repo name." });
        const available = await githubRepos();
        // Only what this GitHub account can actually see gets added, so a typo or a crafted name never reaches `gh repo clone`.
        const known = new Set(available.map((r) => r.slug));
        const unknown = add.find((s: string) => !known.has(s));
        if (unknown) return send(res, 400, { error: `${unknown} isn't visible to the GitHub account on this server.` });
        const owners = Array.isArray(body.autoOwners) ? body.autoOwners.map(String).filter((o: string) => available.some((r) => r.owner === o)) : loadAutoWatch(db).owners;
        const { dir, list } = cfg.repos;
        applyRepoChange(db, dir, list, watchedList(), add, remove);
        saveAutoWatch(db, owners, available);
        // Stopping is immediate: the clone stays, and the project just leaves the graph.
        const ignored: string[] = JSON.parse(setting("ignored") ?? "[]");
        for (const path of ignored) db.prepare("DELETE FROM projects WHERE path = ?").run(path);
        updateRepoIssues(db, [...remove], []);
        clearPrCache();
        if (!add.length) return send(res, 200, { ok: true });
        return send(res, 202, startRepoJob("import", add));
      }
      if (p === "/api/repos/scan") {
        if (!cfg.repos) return send(res, 400, { error: LOCAL_ONLY });
        const slugs = Array.isArray(body.slugs) ? body.slugs : [];
        const watched = new Set(watchedList());
        if (!slugs.length || !slugs.every((s: unknown) => validSlug(s) && watched.has(s))) return send(res, 400, { error: "That repo isn't being watched." });
        return send(res, 202, startRepoJob("scan", slugs));
      }
      send(res, 404, { error: "not found" });
    } catch (e) {
      console.error(`${req.method} ${req.url} failed:`, e);
      send(res, 400, { error: (e as Error).message });
    }
  });

  resetInterrupted(db);
  setInterval(() => { void pollAgentsNow(); void pollLensesNow(); void pollReviewsNow(); }, 2 * 60_000).unref();

  server.listen(port, cfg.host, () => {
    setImmediate(() => overview(db)); // warm the slow part, so the first page load is quick
    console.log(`🍄 Mycelium at ${baseUrl}/  ${auth ? "(sign-in on)" : "(this computer only)"}  (Ctrl-C to stop)`);
    void pollAgentsNow();
    void pollLensesNow();
    void pollReviewsNow();
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
