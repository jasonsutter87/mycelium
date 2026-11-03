// Closing the loop on PRs Mycelium opened: which findings each PR fixes, whether it's merged,
// and whether pulling it into your folder is safe. Never pulls on its own; `pull` is an explicit action.

import { execFile, execFileSync } from "node:child_process";
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
    const raw = await run("gh", repo, ["pr", "list", "--state", "all", "--limit", "50", "--search", `head:${BRANCH_PREFIX}`,
      "--json", "number,url,state,headRefName,baseRefName,headRefOid,mergeCommit"]);
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
    for (const p of prs) {
      const now = new Date().toISOString();
      const { id } = upsert.get(repo, p.number, p.url, p.state, p.headRefName, p.baseRefName, p.headRefOid ?? null, p.mergeCommit?.oid ?? null, now) as { id: number };
      count++;
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
    const pulled = p.merge_oid && git(p.repo, ["merge-base", "--is-ancestor", p.merge_oid, "HEAD"]) !== null;
    if (pulled) continue; // done: nothing to show
    out.push({ pr, needsPull: true, ...pullCheck(p.repo, p.base) });
  }
  return out;
}

/** Is `git merge --ff-only origin/<base>` safe in this folder right now? */
function pullCheck(repo: string, base: string): { ready: boolean; reason?: string } {
  const branch = git(repo, ["branch", "--show-current"]);
  if (branch !== base) return { ready: false, reason: `you're on ${branch || "a detached HEAD"}; the PR merged into ${base}` };
  // Uncommitted edits are fine: a fast-forward that would touch an edited file is refused by git itself.
  if (!git(repo, ["rev-parse", "--verify", "-q", `origin/${base}`])) return { ready: false, reason: `origin/${base} not fetched yet: click Rescan` };
  const ahead = Number(git(repo, ["rev-list", "--count", `origin/${base}..HEAD`]) ?? 0);
  if (ahead) return { ready: false, reason: `local ${base} has ${ahead} unpushed commit(s); pull/rebase it yourself` };
  return { ready: true };
}

/** The ⬇ Pull button: re-check safety, fast-forward only, rescan the project. */
export function pullProject(db: DatabaseSync, projectPath: string): { pulled: string[]; refused: string[] } {
  const res = { pulled: [] as string[], refused: [] as string[] };
  for (const s of projectPrs(db, projectPath).filter((x) => x.needsPull)) {
    const { repo, base } = s.pr;
    if (res.pulled.includes(repo)) continue;
    git(repo, ["fetch", "-q", "origin", base]);
    const check = pullCheck(repo, base);
    if (!check.ready) {
      res.refused.push(`${basename(repo)}: ${check.reason}`);
      continue;
    }
    try {
      execFileSync("git", ["merge", "--ff-only", "-q", `origin/${base}`], { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (e: any) {
      const why = String(e.stderr ?? "").includes("would be overwritten")
        ? "the update touches files you've edited and haven't committed; commit or stash them, then pull"
        : String(e.stderr ?? e.message).split("\n")[0];
      res.refused.push(`${basename(repo)}: ${why}`);
      continue;
    }
    res.pulled.push(repo);
  }
  if (res.pulled.length) saveProject(db, scanProject(projectPath));
  return res;
}
