// The small rule-based agents that watch every open PR, each with its own check on GitHub:
//   Mycelium keys: no API keys in anything the PR commits
//   Mycelium fungi: no new known-vulnerable packages from the PR's lockfile changes
// No AI, so they cost nothing per PR and also run where the AI reviewer doesn't: dependency bots and forks.
// They only read git objects and never run anything from a PR.

import { execFile } from "node:child_process";
import { basename } from "node:path";
import { promisify } from "node:util";
import type { DatabaseSync } from "node:sqlite";
import { emailConfigured, loadAlertSettings, resendSender, type Sender } from "./alerts.ts";
import { scanPatch, type KeyHit } from "./keys.ts";
import { checkPackages, severityRank, type PackageVuln } from "./osv.ts";
import { fetchPrObjects, type GithubPort, type OpenPr } from "./review.ts";
import { parseLockText } from "./scan.ts";

const execFileP = promisify(execFile);
const git = async (repo: string, args: string[]) => (await execFileP("git", args, { cwd: repo, encoding: "utf8", timeout: 180_000, maxBuffer: 1 << 28 })).stdout;

export type AgentName = "keys" | "fungi";
export const AGENT_CONTEXT: Record<AgentName, string> = { keys: "Mycelium keys", fungi: "Mycelium fungi" };

export interface AgentSettings {
  keys: boolean;
  fungi: boolean;
  fungiAutoFix: boolean; // after the nightly check, open fix PRs for high and critical production findings
  seen: Record<AgentName, string[]>; // repos that have answered since each agent was turned on. PRs open at that first answer wait until they change
}
export const DEFAULT_AGENTS: AgentSettings = { keys: false, fungi: false, fungiAutoFix: false, seen: { keys: [], fungi: [] } };

export const loadAgentSettings = (db: DatabaseSync): AgentSettings => {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'agents'").get() as { value: string } | undefined;
  return row ? { ...DEFAULT_AGENTS, ...JSON.parse(row.value) } : DEFAULT_AGENTS;
};
const writeSettings = (db: DatabaseSync, s: AgentSettings) =>
  db.prepare("INSERT INTO settings (key, value) VALUES ('agents', ?) ON CONFLICT DO UPDATE SET value = excluded.value").run(JSON.stringify(s));

export function saveAgentSettings(db: DatabaseSync, input: Partial<AgentSettings>): AgentSettings {
  const prev = loadAgentSettings(db);
  const keys = !!(input.keys ?? prev.keys), fungi = !!(input.fungi ?? prev.fungi);
  const seen = { keys: keys && prev.keys ? prev.seen.keys : [], fungi: fungi && prev.fungi ? prev.seen.fungi : [] };
  const settings: AgentSettings = { keys, fungi, fungiAutoFix: !!(input.fungiAutoFix ?? prev.fungiAutoFix), seen };
  writeSettings(db, settings);
  return settings;
}

const SCHEMA = `CREATE TABLE IF NOT EXISTS agent_checks (
  repo TEXT NOT NULL, number INTEGER NOT NULL, sha TEXT NOT NULL, agent TEXT NOT NULL,
  title TEXT NOT NULL, url TEXT NOT NULL,
  state TEXT NOT NULL,       -- passed | failed | skipped
  details TEXT NOT NULL DEFAULT '[]',
  note TEXT, comment_id INTEGER, checked_at TEXT NOT NULL,
  PRIMARY KEY (repo, number, sha, agent)
)`;

// ---------------------------------------------------------------- key watcher

export async function checkKeys(repo: string, p: Pick<OpenPr, "baseSha" | "sha">): Promise<KeyHit[]> {
  return scanPatch(await git(repo, ["-c", "core.quotePath=false", "log", "-p", "--format=commit:%H", "--no-ext-diff", "--no-textconv", "--no-color", "-U0", `${p.baseSha}..${p.sha}`]));
}

export function keysComment(repo: string, hits: KeyHit[]): string {
  const rows = hits.map((h) => {
    const safe = h.file.replace(/[`[\]<>]/g, "");
    const place = `${safe}${h.line ? `:${h.line}` : ""}`;
    const link = h.commit ? `https://github.com/${repo}/blob/${h.commit}/${safe.split("/").map(encodeURIComponent).join("/")}${h.line ? `#L${h.line}` : ""}` : "";
    return `- **${h.kind}** in ${link ? `[\`${place}\`](${link})` : `\`${place}\``}`;
  });
  return `<!-- mycelium-keys -->\n## 🔑 Mycelium keys: possible key committed\n\n${rows.join("\n")}\n\n**If it's real, replace it first.** It has already been pushed to GitHub, so treat it as leaked, and deleting it in a new commit doesn't remove it from the branch's history.\n\n<sub>The value isn't shown here on purpose. For a test value, add \`mycelium:allow-key\` to that line.</sub>`;
}

// ---------------------------------------------------------------- fungi

export interface FungiResult { added: (PackageVuln & { lockfile: string })[]; manifestOnly: string[] }
export const FUNGI_BLOCKS = (v: PackageVuln) => v.vulnId.startsWith("MAL-") || severityRank(v.severity) >= severityRank("HIGH");

const LOCK_NAME = /^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|packages\.lock\.json|poetry\.lock|uv\.lock|Pipfile\.lock|go\.mod)$/;

const parseAt = async (repo: string, sha: string, path: string) => {
  try {
    return parseLockText(basename(path), await git(repo, ["show", `${sha}:${path}`]));
  } catch {
    return []; // not in that commit: every package counts as new
  }
};

/** Only what this PR brings in. A package that was already on the base branch stays with Findings and the normal fix flow. */
export async function checkDependencies(repo: string, p: Pick<OpenPr, "baseSha" | "sha">, check: typeof checkPackages = checkPackages): Promise<FungiResult> {
  const changed = (await git(repo, ["diff", "--name-only", "--no-renames", `${p.baseSha}...${p.sha}`])).split("\n").filter(Boolean);
  const locks = changed.filter((f) => LOCK_NAME.test(basename(f)));
  const dirOf = (f: string) => f.slice(0, Math.max(0, f.lastIndexOf("/")));
  const manifestOnly = changed.filter((f) => basename(f) === "package.json" && !locks.some((l) => dirOf(l) === dirOf(f)));
  const fresh = new Map<string, { ecosystem: string; name: string; version: string; lockfile: string }>();
  for (const lock of locks) {
    const key = (x: { name: string; version: string }) => `${x.name}@${x.version}`;
    const before = new Set((await parseAt(repo, p.baseSha, lock)).map(key));
    for (const pkg of await parseAt(repo, p.sha, lock)) {
      if (!before.has(key(pkg)) && !fresh.has(`${pkg.ecosystem}|${key(pkg)}`)) fresh.set(`${pkg.ecosystem}|${key(pkg)}`, { ...pkg, lockfile: lock });
    }
  }
  const list = [...fresh.values()];
  const added = (await check(list)).map((v) => ({ ...v, lockfile: list.find((x) => x.name === v.name && x.version === v.version && x.ecosystem === v.ecosystem)!.lockfile }));
  return { added: added.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)), manifestOnly };
}

const plain = (s: string) => s.replace(/:\/\//g, " ").replace(/[<>[\]`@!#]/g, " ").replace(/\s+/g, " ").trim(); // advisory text comes from outside

export function fungiComment(r: FungiResult): string {
  const row = (v: FungiResult["added"][number]) => `| ${v.vulnId.startsWith("MAL-") ? "MALICIOUS" : v.severity} | \`${plain(v.name)}\` ${plain(v.version)} | ${v.fixed ? plain(v.fixed) : "no fix yet"} | [${plain(v.vulnId)}](https://osv.dev/vulnerability/${encodeURIComponent(v.vulnId)}) ${plain(v.summary).slice(0, 120)} |`;
  const blocking = r.added.filter(FUNGI_BLOCKS);
  return `<!-- mycelium-fungi -->\n## 🍄 Mycelium fungi: ${blocking.length ? `this PR adds ${blocking.length} vulnerable package version${blocking.length === 1 ? "" : "s"}` : "this PR adds lower-severity advisories"}\n\n| Severity | Package | Fixed in | Advisory |\n|---|---|---|---|\n${r.added.map(row).join("\n")}\n\n<sub>Only what this PR adds. Upgrade these on this branch and push. The check runs again on the new commit.</sub>`;
}

// ---------------------------------------------------------------- the poll

export interface AgentDeps { github: GithubPort; repoPath(slug: string): string | null; baseUrl: string | null; send?: Sender; log?: (s: string) => void; check?: typeof checkPackages }

export async function pollAgents(db: DatabaseSync, repos: string[], deps: AgentDeps): Promise<{ checked: number; failed: number }> {
  db.exec(SCHEMA);
  const settings = loadAgentSettings(db);
  const enabled = (["keys", "fungi"] as AgentName[]).filter((a) => settings[a]);
  if (!enabled.length) return { checked: 0, failed: 0 };
  const listing = await deps.github.listOpenPrs(repos);
  if (repos.length && !listing.answered.length) throw new Error("GitHub didn't answer for any watched repo. Check that `gh auth status` works on this server.");
  const open = listing.prs.filter((p) => !p.draft);
  const seen = db.prepare("SELECT 1 FROM agent_checks WHERE repo = ? AND number = ? AND sha = ? AND agent = ?");
  const put = db.prepare("INSERT OR REPLACE INTO agent_checks (repo, number, sha, agent, title, url, state, details, note, comment_id, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  const target = deps.baseUrl?.startsWith("https://") ? deps.baseUrl : null;
  let checked = 0, failed = 0, firstError: unknown = null;
  for (const agent of enabled) {
    const seenRepos = new Set(settings.seen[agent]);
    for (const p of open) {
      if (seen.get(p.repo, p.number, p.sha, agent)) continue;
      const now = new Date().toISOString();
      if (!seenRepos.has(p.repo)) {
        put.run(p.repo, p.number, p.sha, agent, p.title, p.url, "skipped", "[]", "Already open when this started on the repo.", null, now);
        continue;
      }
      const repo = deps.repoPath(p.repo);
      if (!repo) continue; // no clone yet: the next sync brings it, and this retries then
      try {
        await fetchPrObjects(repo, p.number, p.baseRef);
        const previous = db.prepare("SELECT comment_id FROM agent_checks WHERE repo = ? AND number = ? AND agent = ? AND comment_id IS NOT NULL ORDER BY checked_at DESC LIMIT 1").get(p.repo, p.number, agent) as { comment_id: number } | undefined;
        let bad = false, description: string, details: unknown[], body: string | null, note: string | null = null;
        if (agent === "keys") {
          const hits = await checkKeys(repo, p);
          bad = hits.length > 0;
          details = hits;
          description = bad ? `${hits.length} possible key${hits.length === 1 ? "" : "s"} committed` : "No keys found";
          body = bad ? keysComment(p.repo, hits) : previous ? "<!-- mycelium-keys -->\n## 🔑 Mycelium keys: no keys in the latest commit\n\nIf an earlier commit in this PR had a real key, it's still in the history, and it still needs replacing." : null;
        } else {
          const r = await checkDependencies(repo, p, deps.check);
          const blocking = r.added.filter(FUNGI_BLOCKS);
          bad = blocking.length > 0;
          details = r.added;
          note = r.manifestOnly.length ? `${r.manifestOnly.join(", ")} changed without a lockfile, so the exact versions couldn't be checked.` : null;
          description = bad ? `Adds ${blocking.length} vulnerable package version${blocking.length === 1 ? "" : "s"}` : r.added.length ? "Only lower-severity advisories added" : "No new vulnerable packages";
          body = r.added.length ? fungiComment(r) : previous ? "<!-- mycelium-fungi -->\n## 🍄 Mycelium fungi: no new vulnerable packages in the latest commit" : null;
        }
        const commentId = body ? await deps.github.comment(p.repo, p.number, previous?.comment_id ?? null, body) : previous?.comment_id ?? null;
        await deps.github.setStatus(p.repo, p.sha, bad ? "failure" : "success", description, target, AGENT_CONTEXT[agent]);
        put.run(p.repo, p.number, p.sha, agent, p.title, p.url, bad ? "failed" : "passed", JSON.stringify(details), note, commentId, now);
        checked++;
        if (bad) {
          failed++;
          await emailFailure(db, agent, p, description, deps);
        }
      } catch (e) {
        // Nothing recorded, so the next poll tries again. One bad repo doesn't stop the rest.
        deps.log?.(`${agent} on ${p.repo}#${p.number}: ${String((e as any)?.stderr || (e as Error)?.message).split("\n")[0]}`);
        firstError ??= e;
      }
    }
  }
  const latest = loadAgentSettings(db);
  writeSettings(db, { ...latest, seen: { keys: latest.keys ? [...new Set([...latest.seen.keys, ...listing.answered])] : [], fungi: latest.fungi ? [...new Set([...latest.seen.fungi, ...listing.answered])] : [] } });
  if (firstError) throw firstError;
  return { checked, failed };
}

async function emailFailure(db: DatabaseSync, agent: AgentName, p: OpenPr, description: string, deps: AgentDeps) {
  const to = loadAlertSettings(db).recipients;
  if (!to.length || !emailConfigured()) return;
  const h = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
  const what = agent === "keys" ? "Possible API key committed" : "New vulnerable package";
  const advice = agent === "keys" ? "If it's real, replace the key first. It's already on GitHub." : "Upgrade it on the PR's branch.";
  try {
    await (deps.send ?? resendSender)({
      to,
      subject: `Mycelium: ${what} in ${p.repo}#${p.number}`.replace(/[\r\n]+/g, " "),
      text: `${description}\n${p.title}\n${p.url}\n\n${advice}`,
      html: `<p><b>${h(description)}</b></p><p><a href="${h(p.url)}">${h(p.repo)}#${p.number}</a> ${h(p.title)}</p><p>${h(advice)}</p>`,
    });
  } catch (e) {
    deps.log?.(`couldn't email about ${p.repo}#${p.number}: ${(e as Error).message}`); // the check and comment are on the PR either way
  }
}

export function agentsView(db: DatabaseSync) {
  db.exec(SCHEMA);
  const rows = db.prepare("SELECT * FROM agent_checks WHERE state != 'skipped' ORDER BY checked_at DESC LIMIT 400").all() as any[];
  const totals = (agent: string) => ({
    checked: rows.filter((r) => r.agent === agent).length,
    failed: rows.filter((r) => r.agent === agent && r.state === "failed").length,
  });
  return {
    settings: loadAgentSettings(db),
    totals: { keys: totals("keys"), fungi: totals("fungi") },
    problems: rows.filter((r) => r.state === "failed").slice(0, 30).map((r) => ({ agent: r.agent, repo: r.repo, number: r.number, sha: r.sha, title: r.title, url: r.url, at: r.checked_at, details: JSON.parse(r.details), note: r.note })),
  };
}
