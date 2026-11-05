// Closing the loop on PRs Mycelium opened: which findings each PR fixes, whether it's merged,
// and whether pulling it into your folder is safe. Pulls only when asked: `pull`, or `fix --all` fast-forwarding
// default branches before it plans (pullBases).

import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

const execFileP = promisify(execFile);
const run = async (cmd: string, cwd: string, args: string[]): Promise<string | null> => {
  try {
    return (await execFileP(cmd, args, { cwd, encoding: "utf8", timeout: 60_000 })).stdout.trim();
  } catch {
    return null;
  }
};
import { basename, dirname, join, relative } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { tx } from "./db.ts";
import { parseLockText, saveProject, scanProject } from "./scan.ts";

const BRANCH_PREFIX = "mycelium/fix-";

function git(cwd: string, args: string[]): string | null {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 60_000 }).trim();
  } catch {
    return null;
  }
}

/** Every git repo that holds a scanned project's lockfiles, with the projects in it. */
async function reposOf(db: DatabaseSync): Promise<Map<string, { projectPath: string; components: string[] }[]>> {
  const rows = db.prepare("SELECT pr.path, c.path AS comp FROM components c JOIN projects pr ON pr.id = c.project_id").all() as { path: string; comp: string }[];
  const dirs = [...new Set(rows.map((r) => dirname(join(r.path, r.comp))))];
  const top = new Map<string, string | null>();
  await pool(dirs, 16, async (d) => void top.set(d, await run("git", d, ["rev-parse", "--show-toplevel"])));
  const out = new Map<string, { projectPath: string; components: string[] }[]>();
  for (const r of rows) {
    const repo = top.get(dirname(join(r.path, r.comp)));
    if (!repo) continue;
    const list = out.get(repo) ?? [];
    let entry = list.find((e) => e.projectPath === r.path);
    if (!entry) list.push((entry = { projectPath: r.path, components: [] }));
    entry.components.push(r.comp);
    out.set(repo, list);
  }
  return out;
}

async function pool<T>(items: T[], n: number, fn: (t: T) => Promise<void>) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]);
  }));
}

/** Ask GitHub about mycelium PRs and record which vulnerable package versions each one removes. */
export async function syncPrs(db: DatabaseSync, log: (s: string) => void = () => {}): Promise<number> {
  let count = 0;
  // Network part in parallel: which repos have mycelium PRs at all.
  const repos = await reposOf(db);
  const found = new Map<string, any[]>();
  await pool([...repos.keys()], 8, async (repo) => {
    const remote = await run("git", repo, ["remote", "get-url", "origin"]);
    if (!remote || !/github\.com[:/]/.test(remote)) return;
    const raw = await run("gh", repo, ["pr", "list", "--state", "all", "--limit", "200", "--search", `head:${BRANCH_PREFIX}`,
      "--json", "number,url,state,headRefName,baseRefName,headRefOid,mergeCommit,title,body,createdAt,mergedAt"]);
    const prs = raw ? (JSON.parse(raw) as any[]).filter((p) => String(p.headRefName).startsWith(BRANCH_PREFIX)) : [];
    if (!prs.length) return;
    // Fresh base branches (for pull checks) and PR heads (to read their lockfiles), fetched by name only.
    const bases = [...new Set(prs.map((p) => p.baseRefName as string))];
    await run("git", repo, ["fetch", "-q", "origin", ...bases]);
    for (const p of prs) {
      if (p.headRefOid && (await run("git", repo, ["cat-file", "-e", `${p.headRefOid}^{commit}`])) === null) {
        await run("git", repo, ["fetch", "-q", "origin", `pull/${p.number}/head`]);
      }
    }
    found.set(repo, prs);
  });
  const vulnerable = db.prepare(`
    SELECT DISTINCT p.name, p.version FROM package_vulns pv JOIN packages p ON p.id = pv.package_id
    JOIN uses u ON u.package_id = p.id JOIN components c ON c.id = u.component_id JOIN projects pr ON pr.id = c.project_id
    WHERE pr.path = ? AND c.path = ?`);
  const upsert = db.prepare(`INSERT INTO prs (repo, number, url, state, head, base, head_oid, merge_oid, synced_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(repo, number) DO UPDATE SET url = excluded.url, state = excluded.state,
    head = excluded.head, base = excluded.base, head_oid = excluded.head_oid, merge_oid = excluded.merge_oid, synced_at = excluded.synced_at
    RETURNING id`);

  for (const [repo, prs] of found) {
    const projects = repos.get(repo)!;
    const owners = projects.map((e) => (db.prepare("SELECT name FROM projects WHERE path = ?").get(e.projectPath) as { name: string }).name);
    for (const p of prs) {
      const now = new Date().toISOString();
      const { id } = upsert.get(repo, p.number, p.url, p.state, p.headRefName, p.baseRefName, p.headRefOid ?? null, p.mergeCommit?.oid ?? null, now) as { id: number };
      count++;
      recordPrHistory(db, p, owners);
      // Read the lockfiles as they are in the PR (pull/N/head survives branch deletion after merge).
      const oid = p.headRefOid as string;
      const fixes: [string, string, string, string][] = [];
      if (p.state !== "CLOSED" && oid) {
        for (const { projectPath, components } of projects) {
          for (const comp of components) {
            const text = git(repo, ["show", `${oid}:${relative(repo, join(projectPath, comp))}`]);
            if (text === null) continue;
            const have = new Set(parseLockText(basename(comp), text).map((x) => `${x.name}@${x.version}`));
            for (const v of vulnerable.all(projectPath, comp) as { name: string; version: string }[]) {
              if (!have.has(`${v.name}@${v.version}`)) fixes.push([projectPath, comp, v.name, v.version]);
            }
          }
        }
      }
      tx(db, () => {
        db.prepare("DELETE FROM pr_fixes WHERE pr_id = ?").run(id);
        const ins = db.prepare("INSERT INTO pr_fixes (pr_id, project_path, component, name, version) VALUES (?, ?, ?, ?, ?)");
        for (const f of fixes) ins.run(id, ...f);
      });
    }
    log(`${basename(repo)}: ${prs.length} Mycelium PR(s)`);
  }
  return count;
}

export interface FixedEntry {
  severity: string;
  name: string;
  from: string;
  to: string | null;
  major: boolean;
  lockfile: string;
  advisories: { id: string; url: string }[];
  moreAdvisories: number; // the PR table lists four and says "+N" for the rest
}

/**
 * What a PR description says it fixed: the "### Fixed" table prBody() writes, plus the shapes of hand-written PRs (a table
 * without some columns, a "### Upgraded" bullet list). [] when it's prose: better a PR with no package list than a guessed one.
 */
export function parseFixedTable(body: string): FixedEntry[] {
  const out: FixedEntry[] = [];
  const lines = String(body ?? "").split(/\r?\n/);
  const start = lines.findIndex((l) => /^### (Fixed|Upgraded)\s*$/.test(l));
  if (start < 0) return out;
  const cellsOf = (l: string) => l.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
  const code = (c = "") => c.replace(/`/g, "");
  let cols: string[] | null = null;
  for (const line of lines.slice(start + 1)) {
    if (line.startsWith("#")) break;
    const bullet = line.match(/^- (\S+)@(\S+) → (\S+)(?: \((.+)\))?\s*$/);
    if (bullet) {
      out.push({ severity: "UNKNOWN", name: bullet[1], from: bullet[2], to: bullet[3], major: false, lockfile: bullet[4] ?? "", advisories: [], moreAdvisories: 0 });
      continue;
    }
    if (!line.startsWith("|")) continue;
    const cells = cellsOf(line);
    if (!cols) {
      if (cells.some((c) => /^package$/i.test(c))) cols = cells.map((c) => c.toLowerCase());
      continue;
    }
    const at = (name: string) => cells[cols!.findIndex((c) => c.startsWith(name))];
    const upgrade = at("upgrade")?.match(/^(\S+)\s*→\s*(.+)$/);
    const name = code(at("package"));
    if (!upgrade || !name) continue; // includes the |---|---| line
    const to = upgrade[2].split(/\s+/)[0];
    const advisories = cells.slice(cols.findIndex((c) => c.startsWith("advisor"))).join(" ");
    out.push({
      severity: /^(CRITICAL|HIGH|MODERATE|LOW)$/.test(at("severity") ?? "") ? at("severity") : "UNKNOWN",
      name, from: upgrade[1], to: to === "null" || to === "removed" ? null : to, major: /major/.test(upgrade[2]), lockfile: code(at("lockfile")),
      advisories: [...advisories.matchAll(/\[([^\]]+)\]\(([^)\s]+)\)/g)].map((m) => ({ id: m[1], url: m[2] })),
      moreAdvisories: Number(advisories.match(/\+(\d+)\s*$/)?.[1] ?? 0),
    });
  }
  return out;
}

/**
 * Saves one PR to the permanent history. `pr` is a row from `gh pr list`; `owners` are the scanned projects its repo belongs to.
 * The project a description names may since have been renamed, so it only wins if it's one of those.
 * Rows are never deleted, so history outlives the scan.
 */
export function recordPrHistory(db: DatabaseSync, pr: any, owners: string[]) {
  const named = String(pr.body ?? "").split("\n")[0].match(/ for \*\*(.+?)\*\*/)?.[1];
  const repo = new URL(pr.url).pathname.split("/").slice(1, 3).join("/");
  const project = named && owners.includes(named) ? named : owners[0] ?? named ?? repo.split("/")[1];
  db.prepare(`INSERT INTO pr_history (url, repo, number, project, state, title, opened_at, merged_at, fixes, synced_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(url) DO UPDATE SET project = excluded.project, state = excluded.state, title = excluded.title,
    opened_at = excluded.opened_at, merged_at = excluded.merged_at, fixes = excluded.fixes, synced_at = excluded.synced_at`)
    .run(pr.url, repo, pr.number, project, pr.state, pr.title ?? "", pr.createdAt ?? null, pr.mergedAt ?? null, JSON.stringify(parseFixedTable(pr.body)), new Date().toISOString());
}

export interface PrInfo {
  number: number;
  url: string;
  state: string;
  base: string;
  repo: string;
}

/** "projectPath|component|name@version" -> the PR that fixes it (prefers merged over open). */
export function prFixIndex(db: DatabaseSync): Map<string, PrInfo> {
  const rows = db.prepare(`SELECT f.project_path, f.component, f.name, f.version, p.number, p.url, p.state, p.base, p.repo
    FROM pr_fixes f JOIN prs p ON p.id = f.pr_id WHERE p.state != 'CLOSED' ORDER BY p.state = 'MERGED'`).all() as any[];
  const m = new Map<string, PrInfo>();
  for (const r of rows) m.set(`${r.project_path}|${r.component}|${r.name}@${r.version}`, { number: r.number, url: r.url, state: r.state, base: r.base, repo: r.repo });
  return m;
}

export interface PullStatus {
  pr: PrInfo;
  needsPull: boolean; // merged on GitHub but not in your folder yet
  ready: boolean; // a fast-forward pull is safe right now
  reason?: string; // why not
}

/** Open PRs and merged-but-not-pulled PRs for a project, with whether a safe pull is possible. */
export function projectPrs(db: DatabaseSync, projectPath: string): PullStatus[] {
  const prs = (db.prepare("SELECT number, url, state, base, repo, merge_oid FROM prs WHERE state != 'CLOSED'").all() as any[])
    .filter((p) => p.repo === projectPath || p.repo.startsWith(projectPath + "/") || projectPath.startsWith(p.repo + "/"));
  const out: PullStatus[] = [];
  for (const p of prs) {
    const pr: PrInfo = { number: p.number, url: p.url, state: p.state, base: p.base, repo: p.repo };
    if (p.state === "OPEN") {
      out.push({ pr, needsPull: false, ready: false });
      continue;
    }
    const pulled = p.merge_oid && (git(p.repo, ["merge-base", "--is-ancestor", p.merge_oid, "HEAD"]) !== null ||
      git(p.repo, ["merge-base", "--is-ancestor", p.merge_oid, `refs/heads/${p.base}`]) !== null);
    if (pulled) continue; // done: nothing to show
    out.push({ pr, needsPull: true, ...pullCheck(p.repo, p.base) });
  }
  return out;
}

/**
 * Can we bring origin/<base> into this folder without anyone resolving conflicts?
 * - nothing local → fast-forward
 * - unpushed local commits → rebase them on top, only if git's merge says they don't conflict with the update
 * - uncommitted edits in files the update touches → stash/re-apply, only if each file merges cleanly
 * Anything else is refused with the reason. Your edits and commits are never dropped.
 */
function pullCheck(repo: string, base: string): { ready: boolean; reason?: string; mode?: "ff" | "rebase" | "merge" } {
  const branch = git(repo, ["branch", "--show-current"]);
  if (branch !== base) return { ready: false, reason: `you're on ${branch || "a detached HEAD"}; the PR merged into ${base}` };
  const up = `origin/${base}`;
  if (!git(repo, ["rev-parse", "--verify", "-q", up])) return { ready: false, reason: `${up} not fetched yet: click Rescan` };
  if (git(repo, ["rev-parse", "-q", "--verify", "REBASE_HEAD"]) || git(repo, ["rev-parse", "-q", "--verify", "MERGE_HEAD"])) {
    return { ready: false, reason: "a merge or rebase is already in progress here: finish it first" };
  }
  const ahead = Number(git(repo, ["rev-list", "--count", `${up}..HEAD`]) ?? 0);
  // What the folder's committed state will be after the pull.
  let result = up;
  if (ahead) {
    const tree = git(repo, ["merge-tree", "--write-tree", "HEAD", up]); // exits non-zero on conflicts
    if (!tree) return { ready: false, reason: `your ${ahead} unpushed commit(s) conflict with the update: pull --rebase and resolve it yourself` };
    result = tree.split("\n")[0];
  }
  // Uncommitted edits: each touched file must merge cleanly (yours vs. HEAD vs. the result).
  const dirty = (git(repo, ["diff", "--name-only", "HEAD"]) ?? "").split("\n").filter(Boolean);
  const changed = new Set((git(repo, ["diff", "--name-only", "HEAD", result]) ?? "").split("\n").filter(Boolean));
  for (const f of dirty.filter((f) => changed.has(f))) {
    if (!mergesCleanly(repo, f, result)) return { ready: false, reason: `your uncommitted edits to ${f} conflict with the update: commit or stash them, then pull` };
  }
  if (!ahead) return { ready: true, mode: "ff" };
  // Rebase only commits that exist nowhere else. If any are already on GitHub (e.g. on main), rewriting them
  // would duplicate history, so merge instead.
  const unpublished = Number(git(repo, ["rev-list", "--count", "HEAD", "--not", "--remotes"]) ?? -1);
  return { ready: true, mode: unpublished === ahead ? "rebase" : "merge" };
}

/** The folder (worktree) of this repo that has `branch` checked out, if any. */
function worktreeOn(repo: string, branch: string): string | null {
  const out = git(repo, ["worktree", "list", "--porcelain"]) ?? "";
  let path = "";
  for (const line of out.split("\n")) {
    if (line.startsWith("worktree ")) path = line.slice(9);
    else if (line === `branch refs/heads/${branch}` && existsSync(path)) return path;
  }
  return null;
}

function mergesCleanly(repo: string, file: string, theirsRev: string): boolean {
  const dir = mkdtempSync(join(tmpdir(), "mycelium-merge-"));
  try {
    const show = (rev: string) => {
      try {
        return execFileSync("git", ["show", `${rev}:${file}`], { cwd: repo, stdio: ["ignore", "pipe", "ignore"], maxBuffer: 256 << 20 });
      } catch {
        return null;
      }
    };
    const base = show("HEAD"), theirs = show(theirsRev);
    if (base === null || theirs === null || !existsSync(join(repo, file))) return false;
    writeFileSync(join(dir, "base"), base);
    writeFileSync(join(dir, "theirs"), theirs);
    writeFileSync(join(dir, "mine"), readFileSync(join(repo, file)));
    execFileSync("git", ["merge-file", "-q", "-p", join(dir, "mine"), join(dir, "base"), join(dir, "theirs")], { stdio: ["ignore", "ignore", "ignore"], maxBuffer: 256 << 20 });
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** GitHub's default branch for `repo` ("main"/"master"), or null if origin has none (no remote, or an empty repo). */
export function defaultBranch(repo: string): string | null {
  const local = git(repo, ["symbolic-ref", "--short", "-q", "refs/remotes/origin/HEAD"]); // "origin/main"
  if (local?.startsWith("origin/")) return local.slice(7);
  const sym = git(repo, ["ls-remote", "--symref", "origin", "HEAD"])?.match(/^ref: refs\/heads\/(\S+)\s+HEAD/m);
  if (sym) return sym[1];
  for (const b of ["main", "master"]) if (git(repo, ["ls-remote", "--exit-code", "--heads", "origin", b])) return b;
  return null;
}

/**
 * Before a fix run: bring each repo's default branch up to date with GitHub, so the scan sees fixes that were
 * already merged and doesn't plan (or PR) them again. Fast-forward only: unpushed commits, conflicting edits or
 * an in-progress merge leave that repo alone and say why. Never rebases, never merges, never switches branches.
 */
export async function pullBases(db: DatabaseSync, log: (s: string) => void = () => {}, only?: Set<string>): Promise<{ pulled: string[]; refused: string[] }> {
  const res = { pulled: [] as string[], refused: [] as string[] };
  const repos = await reposOf(db);
  const done = new Set<string>();
  const targets: { repo: string; base: string; projects: string[] }[] = [];
  // Folders that are worktrees of one repo share a git dir: pull once, rescan every project in any of them.
  const commonOf = new Map<string, string>();
  for (const repo of repos.keys()) commonOf.set(repo, git(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"]) ?? repo);
  for (const [repo, entries] of repos) {
    if (only && !entries.some((e) => only.has(e.projectPath))) continue;
    const common = commonOf.get(repo)!;
    if (done.has(common)) continue;
    done.add(common);
    if (!git(repo, ["remote", "get-url", "origin"])) continue; // nothing to pull from
    const base = defaultBranch(repo);
    const projects = [...repos].filter(([r]) => commonOf.get(r) === common).flatMap(([, es]) => es.map((e) => e.projectPath));
    if (base) targets.push({ repo, base, projects });
  }
  await pool(targets, 8, async ({ repo, base }) => void (await run("git", repo, ["fetch", "-q", "origin", base])));
  const rescan = new Set<string>();
  for (const { repo, base, projects } of targets) {
    const name = basename(repo);
    const before = res.pulled.length;
    if (!git(repo, ["rev-parse", "--verify", "-q", `origin/${base}`])) continue;
    const holder = worktreeOn(repo, base);
    if (!holder) {
      // Not checked out anywhere: move the branch ref itself, only if it's strictly behind.
      if (!git(repo, ["rev-parse", "--verify", "-q", `refs/heads/${base}`])) continue;
      const ahead = Number(git(repo, ["rev-list", "--count", `origin/${base}..refs/heads/${base}`]) ?? 0);
      const behind = Number(git(repo, ["rev-list", "--count", `refs/heads/${base}..origin/${base}`]) ?? 0);
      if (!behind) continue;
      if (ahead) res.refused.push(`${name}: local ${base} has ${ahead} unpushed commit(s)`);
      else if (git(repo, ["update-ref", `refs/heads/${base}`, `origin/${base}`, `refs/heads/${base}`]) === null) res.refused.push(`${name}: couldn't fast-forward ${base}`);
      else res.pulled.push(`${name}: ${base} +${behind}`);
      continue;
    }
    const behind = Number(git(holder, ["rev-list", "--count", `HEAD..origin/${base}`]) ?? 0);
    if (!behind) continue;
    const check = pullCheck(holder, base);
    if (!check.ready || check.mode !== "ff") {
      res.refused.push(`${name}: ${check.reason ?? `your ${base} has unpushed commits: pull it yourself`}`);
      continue;
    }
    try {
      execFileSync("git", ["merge", "--ff-only", "-q", "--autostash", `origin/${base}`], { cwd: holder, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      res.pulled.push(`${name}: ${base} +${behind}`);
    } catch (e: any) {
      res.refused.push(`${name}: ${String(e.stderr ?? e.message).split("\n")[0]}`);
    }
    if (res.pulled.length > before) projects.forEach((p) => rescan.add(p));
  }
  // The scan reads your folders: anything that moved gets re-read now, so the plan matches what's on main.
  for (const p of rescan) if (existsSync(p)) saveProject(db, scanProject(p));
  for (const p of res.pulled) log(`⬇ pulled ${p}`);
  for (const r of res.refused) log(`· not pulled ${r}`);
  return res;
}

/** The ⬇ Pull button: re-check safety, then fast-forward (or rebase unpushed commits), keeping uncommitted edits. */
export function pullProject(db: DatabaseSync, projectPath: string): { pulled: string[]; refused: string[] } {
  const res = { pulled: [] as string[], refused: [] as string[] };
  const done = new Set<string>();
  for (const s of projectPrs(db, projectPath).filter((x) => x.needsPull)) {
    let { repo, base } = s.pr;
    // Folders that are worktrees of one repo share branches: handle each repo + base once.
    const common = git(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"]) ?? repo;
    if (done.has(`${common}|${base}`)) continue;
    done.add(`${common}|${base}`);
    git(repo, ["fetch", "-q", "origin", base]);
    // Is <base> checked out in some folder? Pull there. If not, fast-forward the branch itself, no checkout needed.
    const holder = worktreeOn(repo, base);
    if (holder) repo = holder;
    else if (git(repo, ["rev-parse", "--verify", "-q", `refs/heads/${base}`])) {
      const ahead = Number(git(repo, ["rev-list", "--count", `origin/${base}..refs/heads/${base}`]) ?? 0);
      const elsewhere = git(repo, ["branch", "--show-current"]) || "a detached HEAD";
      if (ahead) res.refused.push(`${basename(repo)}: local ${base} has ${ahead} unpushed commit(s) and isn't checked out anywhere: check it out and pull it yourself`);
      else if (git(repo, ["fetch", "-q", "origin", `${base}:${base}`]) === null) res.refused.push(`${basename(repo)}: couldn't fast-forward ${base}`);
      else res.pulled.push(`${basename(repo)}: updated your local ${base} (not checked out in any folder). This folder is on ${elsewhere}: merge ${base} into it when you want the fix there`);
      continue;
    }
    const check = pullCheck(repo, base);
    if (!check.ready) {
      res.refused.push(`${basename(repo)}: ${check.reason}`);
      continue;
    }
    const args = check.mode === "rebase" ? ["rebase", "-q", "--autostash", `origin/${base}`]
      : check.mode === "merge" ? ["merge", "-q", "--no-edit", "--autostash", `origin/${base}`]
      : ["merge", "--ff-only", "-q", "--autostash", `origin/${base}`];
    try {
      execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (e: any) {
      if (check.mode === "rebase") git(repo, ["rebase", "--abort"]); // back to exactly where you were
      if (check.mode === "merge") git(repo, ["merge", "--abort"]);
      const stashed = (git(repo, ["stash", "list"]) ?? "").includes("autostash");
      res.refused.push(`${basename(repo)}: ${String(e.stderr ?? e.message).split("\n")[0]}` + (stashed ? " (your uncommitted edits are safe in `git stash list`)" : ""));
      continue;
    }
    res.pulled.push(check.mode === "rebase" ? `${repo} (rebased your unpushed commits on top)` : check.mode === "merge" ? `${repo} (merged; your branch had commits GitHub's ${base} doesn't)` : repo);
  }
  if (res.pulled.length) saveProject(db, scanProject(projectPath));
  return res;
}
