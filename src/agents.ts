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
import { agentOnFor, loadRepoChoices } from "./repos.ts";
import { aiBudgetLeft, dropAiRun, fetchPrObjects, neutralise, prepareDiff, recordAiRun, type GithubPort, type OpenPr, type ReviewEngine, type ReviewFinding, type ReviewResult } from "./review.ts";
import { AI_LENSES, aiLens, type AiLens } from "./lenses.ts";
import { parseLockText } from "./scan.ts";

const execFileP = promisify(execFile);
const git = async (repo: string, args: string[]) => (await execFileP("git", args, { cwd: repo, encoding: "utf8", timeout: 180_000, maxBuffer: 1 << 28 })).stdout;
// AI agents, like the reviewer, skip forks and dependency bots: untrusted or low-value, and each one spends the plan.
const DEPENDENCY_BOT = /^(dependabot|renovate|github-actions)(\[bot\])?$/i;

export type AgentName = "keys" | "fungi" | "crimson" | "a11y";
export const RULE_AGENTS: AgentName[] = ["keys", "fungi"];
const AI_AGENT_IDS = AI_LENSES.map((l) => l.id) as AgentName[];
export const ALL_AGENTS: AgentName[] = [...RULE_AGENTS, ...AI_AGENT_IDS];
export const AGENT_CONTEXT: Record<AgentName, string> = { keys: "Mycelium keys", fungi: "Mycelium fungi", ...Object.fromEntries(AI_LENSES.map((l) => [l.id, l.context])) } as Record<AgentName, string>;

export interface AgentSettings {
  keys: boolean;
  fungi: boolean;
  fungiAutoFix: boolean; // after the nightly check, open fix PRs for high and critical production findings
  crimson: boolean; // red-team AI lens: is this change trying to do something harmful on purpose
  a11y: boolean; // accessibility AI lens, advisory only
  seen: Record<AgentName, string[]>; // repos that have answered since each agent was turned on. PRs open at that first answer wait until they change
}
export const DEFAULT_AGENTS: AgentSettings = { keys: false, fungi: false, fungiAutoFix: false, crimson: false, a11y: false, seen: { keys: [], fungi: [], crimson: [], a11y: [] } };

export const loadAgentSettings = (db: DatabaseSync): AgentSettings => {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'agents'").get() as { value: string } | undefined;
  const base = row ? { ...DEFAULT_AGENTS, ...JSON.parse(row.value) } : DEFAULT_AGENTS;
  return { ...base, seen: { ...DEFAULT_AGENTS.seen, ...base.seen } }; // an older record has no seen list for a newer agent
};
const writeSettings = (db: DatabaseSync, s: AgentSettings) =>
  db.prepare("INSERT INTO settings (key, value) VALUES ('agents', ?) ON CONFLICT DO UPDATE SET value = excluded.value").run(JSON.stringify(s));

export function saveAgentSettings(db: DatabaseSync, input: Partial<AgentSettings>): AgentSettings {
  const prev = loadAgentSettings(db);
  const on = Object.fromEntries(ALL_AGENTS.map((a) => [a, !!(input[a] ?? prev[a])])) as Record<AgentName, boolean>;
  // Turning an agent off and on again re-baselines it: its open PRs wait until they change, so it doesn't flag a backlog at once.
  const seen = Object.fromEntries(ALL_AGENTS.map((a) => [a, on[a] && prev[a] ? prev.seen[a] : []])) as Record<AgentName, string[]>;
  const settings: AgentSettings = { ...on, fungiAutoFix: !!(input.fungiAutoFix ?? prev.fungiAutoFix), seen };
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
  const flags = ["--text", "--no-ext-diff", "--no-textconv", "--no-color", "-U0"];
  // Commit by commit catches a key added then deleted. The whole-PR diff catches one that came in through a merge, which git log leaves out.
  const history = scanPatch(await git(repo, ["-c", "core.quotePath=false", "log", "-p", "--format=commit:%H", ...flags, `${p.baseSha}..${p.sha}`]));
  const final = scanPatch(await git(repo, ["-c", "core.quotePath=false", "diff", ...flags, `${p.baseSha}...${p.sha}`])).map((h) => ({ ...h, commit: p.sha }));
  const known = new Set(history.map((h) => `${h.kind}|${h.file}`));
  return [...history, ...final.filter((h) => !known.has(`${h.kind}|${h.file}`))];
}

export function keysComment(repo: string, hits: KeyHit[]): string {
  const rows = hits.slice(0, 100).map((h) => {
    const safe = h.file.replace(/[`[\]<>]/g, "");
    const place = `${safe}${h.line ? `:${h.line}` : ""}`;
    const link = h.commit ? `https://github.com/${repo}/blob/${h.commit}/${safe.split("/").map(encodeURIComponent).join("/")}${h.line ? `#L${h.line}` : ""}` : "";
    return `- **${h.kind}** in ${link ? `[\`${place}\`](${link})` : `\`${place}\``}`;
  });
  return `<!-- mycelium-keys -->\n## 🔑 Mycelium keys: possible key committed\n\n${rows.join("\n")}${hits.length > 100 ? `\n\n_And ${hits.length - 100} more._` : ""}\n\n**If it's real, replace it first.** It has already been pushed to GitHub, so treat it as leaked, and deleting it in a new commit doesn't remove it from the branch's history.\n\n<sub>The value isn't shown here on purpose. For a test value, add \`mycelium:allow-key\` to that line.</sub>`;
}

// ---------------------------------------------------------------- fungi

export interface FungiResult {
  added: (PackageVuln & { lockfile: string })[];
  uncheckable: string[]; // dependency files that changed but can't be checked: no lockfile, or one this can't read
  unreadable: string[]; // lockfiles that wouldn't parse, like ones with merge conflict markers
}
// UNKNOWN blocks too: an advisory with no usable score hasn't been shown to be minor.
export const FUNGI_BLOCKS = (v: PackageVuln) => v.vulnId.startsWith("MAL-") || v.severity === "UNKNOWN" || severityRank(v.severity) >= severityRank("HIGH");

// What parseLockText can read, so exact versions can be compared.
const LOCK_NAME = /^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|packages\.lock\.json|poetry\.lock|uv\.lock|Pipfile\.lock|go\.mod|requirements.*\.txt|.*\.(?:cs|fs|vb)proj|build\.gradle(?:\.kts)?)$/;
// These only give ranges: fine if a lockfile beside or above them changed too, a gap if not.
const NEEDS_LOCK = /^(package\.json|Cargo\.toml|pyproject\.toml|Pipfile)$/;

const UNSUPPORTED = /^(bun\.lockb?|Gemfile(\.lock)?|composer\.(lock|json)|gradle\.lockfile|pom\.xml|Directory\.Packages\.props)$/;

/** Empty when the file isn't in that commit. Null when it's there but can't be parsed. A failure in git itself throws, and the poll retries. */
const parseAt = async (repo: string, sha: string, path: string) => {
  try {
    await git(repo, ["cat-file", "-e", `${sha}:${path}`]);
  } catch {
    return [];
  }
  const text = await git(repo, ["show", `${sha}:${path}`]);
  if (/^(<<<<<<<|>>>>>>>) /m.test(text)) return null;
  try {
    return parseLockText(basename(path), text);
  } catch {
    return null;
  }
};

/** Only what this PR brings in. A package that was already on the base branch stays with Findings and the normal fix flow. */
export async function checkDependencies(repo: string, p: Pick<OpenPr, "baseSha" | "sha">, check: typeof checkPackages = checkPackages): Promise<FungiResult> {
  // Compared with where the branch left off: a package that only changed on the base branch since then isn't this PR's doing.
  const forkPoint = (await git(repo, ["merge-base", p.baseSha, p.sha])).trim();
  const changed = (await git(repo, ["-c", "core.quotePath=false", "diff", "--name-only", "--no-renames", `${forkPoint}...${p.sha}`])).split("\n").filter(Boolean);
  const locks = changed.filter((f) => LOCK_NAME.test(basename(f)));
  const dirOf = (f: string) => f.slice(0, Math.max(0, f.lastIndexOf("/")));
  const covers = (lock: string, f: string) => dirOf(lock) === "" || dirOf(f) === dirOf(lock) || dirOf(f).startsWith(`${dirOf(lock)}/`);
  const unsupported = changed.filter((f) => UNSUPPORTED.test(basename(f)));
  const uncheckable = [...unsupported, ...changed.filter((f) => NEEDS_LOCK.test(basename(f)) && !locks.some((l) => covers(l, f)) && !unsupported.some((l) => covers(l, f)))];
  // go.sum only ever changes with its go.mod, which is read. On its own it's a gap.
  for (const f of changed) if (basename(f) === "go.sum" && !locks.some((l) => basename(l) === "go.mod" && dirOf(l) === dirOf(f))) uncheckable.push(f);
  const unreadable: string[] = [];
  const fresh = new Map<string, { ecosystem: string; name: string; version: string; lockfile: string }>();
  for (const lock of locks) {
    const key = (x: { name: string; version: string }) => `${x.name}@${x.version}`;
    const older = await parseAt(repo, forkPoint, lock), newer = await parseAt(repo, p.sha, lock);
    if (!older || !newer) { unreadable.push(lock); continue; }
    const before = new Set(older.map(key));
    for (const pkg of newer) {
      if (!before.has(key(pkg)) && !fresh.has(`${pkg.ecosystem}|${key(pkg)}`)) fresh.set(`${pkg.ecosystem}|${key(pkg)}`, { ...pkg, lockfile: lock });
    }
  }
  const list = [...fresh.values()];
  const added = (await check(list)).map((v) => ({ ...v, lockfile: list.find((x) => x.name === v.name && x.version === v.version && x.ecosystem === v.ecosystem)!.lockfile }));
  return { added: added.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)), uncheckable, unreadable };
}

const MAX_ROWS = 100; // a table this long has made its point, and GitHub refuses comments over 65,536 characters
const plain = (s: string) => s.replace(/:\/\//g, " ").replace(/[<>[\]`@!#]/g, " ").replace(/\s+/g, " ").trim(); // advisory text comes from outside

export function fungiComment(r: FungiResult): string {
  const row = (v: FungiResult["added"][number]) => `| ${v.vulnId.startsWith("MAL-") ? "MALICIOUS" : v.severity} | \`${plain(v.name)}\` ${plain(v.version)} | ${v.fixed ? plain(v.fixed) : "no fix yet"} | [${plain(v.vulnId)}](https://osv.dev/vulnerability/${encodeURIComponent(v.vulnId)}) ${plain(v.summary).slice(0, 120)} |`;
  const blocking = r.added.filter(FUNGI_BLOCKS);
  const shown = r.added.slice(0, MAX_ROWS);
  const title = blocking.length ? `this PR adds ${blocking.length} vulnerable package version${blocking.length === 1 ? "" : "s"}` : r.unreadable.length ? "couldn't read a lockfile" : r.added.length ? "this PR adds lower-severity advisories" : "couldn't check everything";
  const table = shown.length ? `| Severity | Package | Fixed in | Advisory |\n|---|---|---|---|\n${shown.map(row).join("\n")}${r.added.length > MAX_ROWS ? `\n\n_And ${r.added.length - MAX_ROWS} more._` : ""}\n\n` : "";
  const list = (l: string[]) => l.slice(0, 40).map((f) => `\`${plain(f)}\``).join(", ") + (l.length > 40 ? `, and ${l.length - 40} more` : "");
  const unread = r.unreadable.length ? `**Couldn't read:** ${list(r.unreadable)}. It may have merge conflict markers in it.\n\n` : "";
  const notChecked = r.uncheckable.length ? `**Not checked:** ${list(r.uncheckable)}. Either there's no lockfile showing exact versions, or it's a kind Fungi can't read yet.\n\n` : "";
  return `<!-- mycelium-fungi -->\n## 🍄 Mycelium fungi: ${title}\n\n${table}${unread}${notChecked}<sub>Only what this PR adds. Upgrade these on this branch and push. The check runs again on the new commit.</sub>`;
}

// ---------------------------------------------------------------- the poll

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const COMMENT_CHARS = 60_000; // GitHub refuses comments over 65,536

/** The PR comment for one AI lens, worst finding first, trimmed to fit. Everything from the model is neutralised. */
export function lensComment(lens: AiLens, repo: string, sha: string, result: ReviewResult): string {
  const ordered = [...result.findings].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  const sections = ordered.map((f) => `### ${f.severity.toUpperCase()}: ${neutralise(f.title).replace(/\s+/g, " ")}${f.file ? ` \u00b7 \`${neutralise(f.file).replace(/[\`\]\[]/g, "")}${f.line > 0 ? `:${f.line}` : ""}\`` : ""}\n\n${neutralise(f.detail)}${f.suggestion ? `\n\n**Fix:** ${neutralise(f.suggestion)}` : ""}`);
  let body = "", dropped = 0;
  for (const sec of sections) { if (body.length + sec.length > COMMENT_CHARS) dropped++; else body += (body ? "\n\n" : "") + sec; }
  if (dropped) body += `\n\n_${dropped} more on the Mycelium dashboard._`;
  const head = lens.advisory
    ? `## ${lens.emoji} Mycelium ${lens.id}: ${lens.foundLabel(result.findings.length)} (advisory, never blocks a merge)`
    : `## ${lens.emoji} Mycelium ${lens.id}: ${result.findings.some(lens.blocks) ? "sent back" : "notes"}`;
  return `<!-- mycelium-${lens.id} -->\n${head}\n\n${neutralise(result.summary).slice(0, 2000)}\n\n${body}\n\n<sub>Reviewed \`${sha.slice(0, 7)}\`. An AI review can miss things, and Mycelium never merges on its own.</sub>`;
}

interface LensOutcome { bad: boolean; description: string; details: ReviewFinding[]; body: string | null; note: string | null }

/** Runs one AI lens on a PR's diff. Uses the same fetch, diff prep, and engine as the reviewer. */
async function runAiLens(engine: ReviewEngine, lens: AiLens, repoPath: string, p: OpenPr, previousComment: boolean): Promise<LensOutcome> {
  await fetchPrObjects(repoPath, p.number, p.baseRef);
  const raw = await git(repoPath, ["-c", "core.quotePath=false", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--find-renames", `${p.baseSha}...${p.sha}`]);
  const { diff, omitted, tooLarge } = prepareDiff(raw);
  if (tooLarge) return { bad: false, description: "Too large to review automatically", details: [], body: null, note: "The diff was too large to review automatically." };
  const { result } = await engine({ repo: p.repo, number: p.number, title: p.title, body: p.body, author: p.author, baseRef: p.baseRef, diff, omitted }, repoPath, p.sha, lens.system);
  const blocking = lens.advisory ? [] : result.findings.filter(lens.blocks);
  const bad = blocking.length > 0;
  const description = bad ? lens.foundLabel(blocking.length) : result.findings.length && lens.advisory ? lens.foundLabel(result.findings.length) : lens.passLabel;
  const body = result.findings.length ? lensComment(lens, p.repo, p.sha, result)
    : previousComment ? `<!-- mycelium-${lens.id} -->\n## ${lens.emoji} Mycelium ${lens.id}: nothing to flag in the latest commit` : null;
  return { bad, description, details: result.findings, body, note: null };
}

export interface AgentDeps { github: GithubPort; repoPath(slug: string): string | null; baseUrl: string | null; send?: Sender; log?: (s: string) => void; check?: typeof checkPackages; engine?: ReviewEngine }

export async function pollAgents(db: DatabaseSync, repos: string[], deps: AgentDeps): Promise<{ checked: number; failed: number }> {
  db.exec(SCHEMA);
  const settings = loadAgentSettings(db);
  const enabled = [...RULE_AGENTS.filter((a) => settings[a]), ...(deps.engine ? AI_AGENT_IDS.filter((a) => settings[a]) : [])];
  if (!enabled.length) return { checked: 0, failed: 0 };
  const choices = loadRepoChoices(db);
  const onFor = (agent: AgentName) => repos.filter((r) => agentOnFor(choices, r, agent));
  const wanted = repos.filter((r) => enabled.some((a) => agentOnFor(choices, r, a)));
  const listing = wanted.length ? await deps.github.listOpenPrs(wanted) : { prs: [], answered: [], partial: [] };
  if (wanted.length && !listing.answered.length) throw new Error("GitHub didn't answer for any watched repo. Check that `gh auth status` works on this server.");
  const open = listing.prs.filter((p) => !p.draft);
  const seen = db.prepare("SELECT 1 FROM agent_checks WHERE repo = ? AND number = ? AND sha = ? AND agent = ?");
  const put = db.prepare("INSERT OR REPLACE INTO agent_checks (repo, number, sha, agent, title, url, state, details, note, comment_id, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  const target = deps.baseUrl?.startsWith("https://") ? deps.baseUrl : null;
  let checked = 0, failed = 0, firstError: unknown = null;
  for (const agent of enabled) {
    const seenRepos = new Set(settings.seen[agent]);
    const onHere = new Set(onFor(agent));
    for (const p of open) {
      if (!onHere.has(p.repo)) continue;
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
        } else if (agent === "fungi") {
          const r = await checkDependencies(repo, p, deps.check);
          const blocking = r.added.filter(FUNGI_BLOCKS);
          bad = blocking.length > 0 || r.unreadable.length > 0;
          details = r.added;
          const gaps = [...r.unreadable, ...r.uncheckable];
          note = gaps.length ? `Couldn't check ${gaps.join(", ")}` : null;
          description = blocking.length ? `Adds ${blocking.length} vulnerable package version${blocking.length === 1 ? "" : "s"}` : r.unreadable.length ? `Couldn't read ${r.unreadable.length} lockfile${r.unreadable.length === 1 ? "" : "s"}` : r.uncheckable.length ? `Couldn't check ${r.uncheckable.length} dependency file${r.uncheckable.length === 1 ? "" : "s"}` : r.added.length ? "Only lower-severity advisories added" : "No new vulnerable packages";
          body = r.added.length || gaps.length ? fungiComment(r) : previous ? "<!-- mycelium-fungi -->\n## 🍄 Mycelium fungi: no new vulnerable packages in the latest commit" : null;
        } else {
          // An AI lens (Crimson, a11y). Skip forks and dependency bots once, and stop at the shared daily limit.
          if (p.fork || DEPENDENCY_BOT.test(p.author ?? "")) {
            put.run(p.repo, p.number, p.sha, agent, p.title, p.url, "skipped", "[]", "From a fork or a dependency bot, so the AI agents skip it.", null, now);
            continue;
          }
          if (aiBudgetLeft(db) <= 0) continue; // out of budget: leave it unrecorded so it runs after the limit resets
          const runId = recordAiRun(db);
          try {
            const out = await runAiLens(deps.engine!, aiLens(agent)!, repo, p, !!previous);
            ({ bad, description, details, body, note } = out);
          } catch (e) {
            dropAiRun(db, runId); // the run never produced a result, so it shouldn't count against the budget
            throw e;
          }
        }
        // The check first: if the comment can't be posted, the PR must still show the result.
        // A repo this account can read but not write to can't take a check. That won't change on a retry, so record the result here and move on.
        try {
          await deps.github.setStatus(p.repo, p.sha, bad ? "failure" : "success", description, target, AGENT_CONTEXT[agent]);
        } catch (e) {
          if (!/HTTP (403|404)/.test(`${(e as any)?.stderr ?? ""} ${(e as Error)?.message ?? ""}`)) throw e;
          body = null;
          note = "This GitHub account can't post to this repo, so the result only shows here.";
        }
        let commentId = previous?.comment_id ?? null;
        if (body) {
          try {
            commentId = await deps.github.comment(p.repo, p.number, commentId, body);
          } catch (e) {
            deps.log?.(`couldn't comment on ${p.repo}#${p.number}: ${String((e as Error)?.message).split("\n")[0]}`);
          }
        }
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
  // A flagged PR that has since closed isn't a to-do any more. Only a complete answer can say it closed.
  const complete = listing.answered.filter((r) => !listing.partial.includes(r));
  const openNow = new Set(listing.prs.map((p) => `${p.repo}#${p.number}`));
  for (const r of db.prepare("SELECT DISTINCT repo, number FROM agent_checks WHERE state = 'failed'").all() as { repo: string; number: number }[]) {
    if (complete.includes(r.repo) && !openNow.has(`${r.repo}#${r.number}`)) db.prepare("UPDATE agent_checks SET state = 'closed' WHERE state = 'failed' AND repo = ? AND number = ?").run(r.repo, r.number);
  }
  const latest = loadAgentSettings(db);
  // A repo that's off drops out, so its open PRs wait again when it's turned back on.
  const nextSeen = (a: AgentName) => {
    if (!latest[a]) return [];
    // Only an agent this pass actually ran for. One switched on while this pass was running hasn't left anything alone yet:
    // marking its repos as seen would make every PR already open look new on its next pass.
    if (!enabled.includes(a)) return latest.seen[a];
    const on = new Set(onFor(a));
    return [...new Set([...latest.seen[a], ...listing.answered])].filter((r) => on.has(r));
  };
  writeSettings(db, { ...latest, seen: Object.fromEntries(ALL_AGENTS.map((a) => [a, nextSeen(a)])) as Record<AgentName, string[]> });
  if (firstError) throw firstError;
  return { checked, failed };
}

async function emailFailure(db: DatabaseSync, agent: AgentName, p: OpenPr, description: string, deps: AgentDeps) {
  const to = loadAlertSettings(db).recipients;
  if (!to.length || !emailConfigured()) return;
  const h = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
  const what = agent === "keys" ? "Possible API key committed" : agent === "fungi" ? "New vulnerable package" : agent === "crimson" ? "Suspicious change flagged by Crimson" : "Issue found";
  const advice = agent === "keys" ? "If it's real, replace the key first. It's already on GitHub." : agent === "fungi" ? "Upgrade it on the PR's branch." : "Read the PR comment and decide before merging.";
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
  const totals = (agent: string) => db.prepare("SELECT count(*) AS checked, COALESCE(sum(state IN ('failed', 'closed')), 0) AS failed FROM agent_checks WHERE agent = ? AND state != 'skipped'").get(agent) as { checked: number; failed: number };
  // Each PR's latest commit per agent: a failure that a later commit fixed is over.
  const choices = loadRepoChoices(db);
  const all = db.prepare(`SELECT * FROM agent_checks a WHERE state IN ('passed', 'failed') AND checked_at = (SELECT max(checked_at) FROM agent_checks b WHERE b.repo = a.repo AND b.number = a.number AND b.agent = a.agent AND b.state != 'skipped') ORDER BY checked_at DESC LIMIT 200`).all() as any[];
  const rows = all.filter((r) => agentOnFor(choices, r.repo, r.agent)); // turned off for a repo means off this list too
  return {
    settings: loadAgentSettings(db),
    totals: { keys: totals("keys"), fungi: totals("fungi"), crimson: totals("crimson"), a11y: totals("a11y") },
    problems: rows.filter((r) => r.state === "failed").slice(0, 30).map((r) => ({ agent: r.agent, repo: r.repo, number: r.number, sha: r.sha, title: r.title, url: r.url, at: r.checked_at, details: JSON.parse(r.details), note: r.note })),
    gaps: rows.filter((r) => r.state === "passed" && r.note).slice(0, 10).map((r) => ({ repo: r.repo, number: r.number, title: r.title, url: r.url, note: r.note })),
  };
}
