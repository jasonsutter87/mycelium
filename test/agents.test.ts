import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentsView, checkDependencies, checkKeys, fungiComment, keysComment, pollAgents, saveAgentSettings, type AgentDeps } from "../src/agents.ts";
import { openDb } from "../src/db.ts";
import { saveRepoChoices } from "../src/repos.ts";
import { describeHits, redactKeys, scanLine, scanPatch } from "../src/keys.ts";
import type { GithubPort, OpenPr, ReviewEngine } from "../src/review.ts";
import { loadAgentSettings } from "../src/agents.ts";
import { EngineTrouble, ReviewFailed } from "../src/review.ts";

// Assembled at run time, so this file doesn't trip the very check it tests.
const GH = "ghp" + "_" + "Ab1".repeat(12);
const AWS = "AKIA" + "Q7ZX2LMN4PRT8VWY";
const lock = (pkgs: Record<string, string>) => JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: {} }, ...Object.fromEntries(Object.entries(pkgs).map(([n, v]) => [`node_modules/${n}`, { version: v }])) } });

function repo() {
  const dir = mkdtempSync(join(tmpdir(), "myc-agents-"));
  const g = (...a: string[]) => execFileSync("git", a, { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  g("init", "-q", "-b", "main"); g("config", "user.email", "t@t.t"); g("config", "user.name", "t");
  writeFileSync(join(dir, "a.ts"), "export const a = 1;\n");
  writeFileSync(join(dir, "package-lock.json"), lock({ old: "1.0.0", shared: "2.0.0" }));
  g("add", "-A"); g("commit", "-qm", "base");
  const base = g("rev-parse", "HEAD");
  const commit = (files: Record<string, string>) => { for (const [f, t] of Object.entries(files)) writeFileSync(join(dir, f), t); g("add", "-A"); g("commit", "-qm", "c"); return g("rev-parse", "HEAD"); };
  return { dir, base, commit, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("known key formats are caught, placeholders and marked test values aren't", () => {
  assert.equal(scanLine(`token = "${GH}"`), "GitHub token");
  assert.equal(scanLine(`aws=${AWS}`), "AWS access key");
  assert.equal(scanLine(["-----BEGIN", "RSA PRIVATE", "KEY-----"].join(" ")), "private key");
  assert.equal(scanLine("AKIAIOSFODNN7EXAMPLE"), null); // mycelium:allow-key
  assert.equal(scanLine(`t = "${GH}" // mycelium:allow-key`), null);
  assert.equal(scanLine("const version = '1.2.3';"), null);
  assert.ok(!redactKeys(`a ${GH} b ${AWS}`).includes("Ab1Ab1"));
});

test("only added lines count, with the right file and line, and the value never appears in the report", () => {
  const patch = `commit:abc\ndiff --git a/x.ts b/x.ts\n--- a/x.ts\n+++ b/x.ts\n@@ -1,0 +5,2 @@\n+const a = 1;\n+const k = "${GH}";\n@@ -20 +22,0 @@\n-const old = "${AWS}";\n`;
  const hits = scanPatch(patch);
  assert.deepEqual(hits, [{ kind: "GitHub token", file: "x.ts", line: 6, commit: "abc" }]);
  assert.ok(!keysComment("o/r", hits).includes(GH) && !describeHits(hits).includes(GH) && !JSON.stringify(hits).includes(GH));
});

test("a secret file is flagged, an example file isn't", () => {
  const f = (n: string) => `diff --git a/${n} b/${n}\n--- /dev/null\n+++ b/${n}\n@@ -0,0 +1 @@\n+A=1\n`;
  assert.equal(scanPatch(f(".env"))[0].kind, "file that holds secrets");
  assert.equal(scanPatch(f("config/.env.production"))[0].kind, "file that holds secrets");
  assert.equal(scanPatch(f("certs/server.pem")).length, 1);
  assert.deepEqual(scanPatch(f(".env.example")), []);
});

test("a key added then deleted within the PR is still caught", async () => {
  const r = repo();
  try {
    r.commit({ "a.ts": `export const k = "${GH}";\n` });
    const sha = r.commit({ "a.ts": "export const a = 2;\n" });
    const hits = await checkKeys(r.dir, { baseSha: r.base, sha });
    assert.equal(hits.length, 1);
    assert.equal(hits[0].file, "a.ts");
  } finally { r.cleanup(); }
});

test("fungi only asks about what the PR adds, and flags a package.json with no lockfile", async () => {
  const r = repo();
  try {
    const sha = r.commit({ "package-lock.json": lock({ old: "1.0.0", shared: "2.1.0", fresh: "3.0.0" }), "package.json": "{}" });
    const asked: string[] = [];
    const out = await checkDependencies(r.dir, { baseSha: r.base, sha }, async (list) => {
      asked.push(...list.map((p) => `${p.ecosystem}:${p.name}@${p.version}`));
      return [{ ecosystem: "npm", name: "fresh", version: "3.0.0", vulnId: "GHSA-1", severity: "HIGH", summary: "bad", fixed: "3.0.1" }];
    });
    assert.deepEqual(asked.sort(), ["npm:fresh@3.0.0", "npm:shared@2.1.0"]);
    assert.equal(out.added[0].lockfile, "package-lock.json");
    assert.deepEqual(out.uncheckable, []);
    assert.match(fungiComment(out), /fresh/);
    const lone = r.commit({ "package.json": '{"name":"x"}' });
    assert.deepEqual((await checkDependencies(r.dir, { baseSha: sha, sha: lone }, async () => [])).uncheckable, ["package.json"]);
  } finally { r.cleanup(); }
});

test("advisory text can't ping people or inject markup", () => {
  const c = fungiComment({ uncheckable: [], unreadable: [], added: [{ ecosystem: "npm", name: "p", version: "1", vulnId: "GHSA-1", severity: "HIGH", summary: "hi @octocat <img src=x> ![a](b)", fixed: null, lockfile: "l" }] });
  assert.ok(!c.includes("@octocat") && !c.includes("<img") && !c.includes("!["));
});

function fake(open: OpenPr[]) {
  const statuses: any[] = [], comments: any[] = [];
  const github: GithubPort = {
    listOpenPrs: async () => ({ prs: open, answered: ["o/r"], partial: [] }),
    setStatus: async (_r, sha, state, description, _t, context) => void statuses.push({ sha, state, description, context }),
    comment: async (_r, number, id, body) => { comments.push({ number, id, body }); return id ?? 7; },
  };
  return { github, statuses, comments };
}
const pr = (r: { base: string }, sha: string, over: Partial<OpenPr> = {}): OpenPr => ({ repo: "o/r", number: 1, title: "T", body: "", url: "https://github.com/o/r/pull/1", author: "dependabot", draft: false, fork: false, sha, baseSha: r.base, baseRef: "main", ...over });

// pollAgents fetches from origin, so the test repo points at itself with a PR ref.
function withOrigin(r: ReturnType<typeof repo>, sha: string) {
  execFileSync("git", ["remote", "add", "origin", r.dir], { cwd: r.dir, stdio: "ignore" });
  execFileSync("git", ["update-ref", "refs/pull/1/head", sha], { cwd: r.dir, stdio: "ignore" });
}

test("baseline, then a failing key check with an email, then a clean commit updates the same comment", async () => {
  const r = repo();
  const env = { k: process.env.RESEND_API_KEY, f: process.env.MYCELIUM_EMAIL_FROM };
  process.env.RESEND_API_KEY = "t"; process.env.MYCELIUM_EMAIL_FROM = "a@b.co";
  try {
    const db = openDb(":memory:");
    db.prepare("INSERT INTO settings (key, value) VALUES ('alerts', ?)").run(JSON.stringify({ enabled: true, recipients: ["me@b.co"], critical: true, highThreshold: 3 }));
    saveAgentSettings(db, { keys: true });
    const first = r.commit({ "a.ts": "export const a = 2;\n" });
    const open = [pr(r, first)];
    const gh = fake(open);
    const mail: any[] = [];
    const deps: AgentDeps = { github: gh.github, repoPath: () => r.dir, baseUrl: null, send: async (m) => void mail.push(m) };
    withOrigin(r, first);
    assert.deepEqual(await pollAgents(db, ["o/r"], deps), { checked: 0, failed: 0 });
    assert.equal(gh.statuses.length, 0, "PRs already open are left alone");

    const bad = r.commit({ "a.ts": `export const k = "${GH}";\n` });
    execFileSync("git", ["update-ref", "refs/pull/1/head", bad], { cwd: r.dir, stdio: "ignore" });
    open[0] = pr(r, bad, { baseSha: first });
    assert.deepEqual(await pollAgents(db, ["o/r"], deps), { checked: 1, failed: 1 });
    assert.deepEqual(gh.statuses.at(-1), { sha: bad, state: "failure", description: "1 possible key committed", context: "Mycelium keys" });
    assert.ok(!gh.comments[0].body.includes(GH) && !JSON.stringify(mail).includes(GH));
    assert.match(mail[0].subject, /Possible API key/);
    assert.equal(agentsView(db).problems.length, 1);
    assert.deepEqual(await pollAgents(db, ["o/r"], deps), { checked: 0, failed: 0 }, "a checked commit isn't checked twice");

    const clean = r.commit({ "a.ts": "export const a = 3;\n" });
    execFileSync("git", ["update-ref", "refs/pull/1/head", clean], { cwd: r.dir, stdio: "ignore" });
    open[0] = pr(r, clean, { baseSha: bad });
    await pollAgents(db, ["o/r"], deps);
    assert.equal(gh.statuses.at(-1).state, "success");
    assert.equal(gh.comments.at(-1).id, 7, "updates its comment");
    assert.match(gh.comments.at(-1).body, /still in the history/);
  } finally {
    r.cleanup();
    for (const [n, v] of [["RESEND_API_KEY", env.k], ["MYCELIUM_EMAIL_FROM", env.f]] as const) { if (v === undefined) delete process.env[n]; else process.env[n] = v; }
  }
});

test("a failed advisory lookup records nothing and retries, and off means off", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    const gh = fake([]);
    assert.deepEqual(await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null }), { checked: 0, failed: 0 });
    saveAgentSettings(db, { fungi: true });
    await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null }); // clears the baseline
    const sha = r.commit({ "package-lock.json": lock({ fresh: "1.0.0" }) });
    withOrigin(r, sha);
    const open = fake([pr(r, sha)]);
    let down = true;
    const check = async () => { if (down) throw new Error("OSV down"); return [{ ecosystem: "npm", name: "fresh", version: "1.0.0", vulnId: "MAL-1", severity: "UNKNOWN", summary: "evil", fixed: null }]; };
    const deps: AgentDeps = { github: open.github, repoPath: () => r.dir, baseUrl: null, check };
    await assert.rejects(pollAgents(db, ["o/r"], deps), /OSV down/);
    assert.equal(open.statuses.length, 0);
    down = false;
    assert.deepEqual(await pollAgents(db, ["o/r"], deps), { checked: 1, failed: 1 });
    assert.equal(open.statuses.at(-1).context, "Mycelium fungi");
    assert.equal(open.statuses.at(-1).state, "failure", "a malicious package fails whatever its severity says");
  } finally { r.cleanup(); }
});

// ---------------------------------------------------------------- what the second real review found

test("binary, renamed and spaced secret files are flagged, and a line that looks like a header can't stop the scan", () => {
  assert.equal(scanPatch("diff --git a/app.p12 b/app.p12\nnew file mode 100644\nBinary files /dev/null and b/app.p12 differ\n")[0].kind, "file that holds secrets");
  assert.equal(scanPatch("diff --git a/notes.txt b/.env\nsimilarity index 100%\nrename from notes.txt\nrename to .env\n")[0].file, ".env");
  assert.equal(scanPatch("diff --git a/.env b/.env\nnew file mode 100644\n")[0].kind, "file that holds secrets");
  assert.equal(scanPatch("diff --git a/my dir/.env b/my dir/.env\n--- /dev/null\n+++ b/my dir/.env\t\n@@ -0,0 +1 @@\n+A=1\n")[0].file, "my dir/.env");
  const tricky = `diff --git a/x.ts b/x.ts\n--- a/x.ts\n+++ b/x.ts\n@@ -0,0 +1,2 @@\n+++ /dev/null\n+const k = "${GH}";\n`;
  assert.deepEqual(scanPatch(tricky), [{ kind: "GitHub token", file: "x.ts", line: 2, commit: null }]);
});

test("fungi compares with where the branch left off, and a broken lockfile doesn't pass", async () => {
  const r = repo();
  try {
    const g = (...a: string[]) => execFileSync("git", a, { cwd: r.dir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    g("checkout", "-q", "-b", "pr");
    const sha = r.commit({ "package-lock.json": lock({ old: "1.0.0", shared: "2.0.0", mine: "1.0.0" }) });
    g("checkout", "-q", "main");
    const moved = r.commit({ "package-lock.json": lock({ old: "1.0.1", shared: "2.0.0" }) });
    const asked: string[] = [];
    await checkDependencies(r.dir, { baseSha: moved, sha }, async (list) => { asked.push(...list.map((p) => p.name)); return []; });
    assert.deepEqual(asked, ["mine"], "old@1.0.0 only looks new because main moved on");

    g("checkout", "-q", "pr");
    const broken = r.commit({ "package-lock.json": "<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> x\n" });
    const out = await checkDependencies(r.dir, { baseSha: moved, sha: broken }, async () => []);
    assert.deepEqual(out.unreadable, ["package-lock.json"]);
    const gem = r.commit({ "Gemfile.lock": "GEM\n" });
    assert.deepEqual((await checkDependencies(r.dir, { baseSha: broken, sha: gem }, async () => [])).uncheckable, ["Gemfile.lock"]);
  } finally { r.cleanup(); }
});

test("the check is set first and comments are capped, so a failed comment can't hide a result", async () => {
  const hits = Array.from({ length: 5000 }, (_, i) => ({ kind: "GitHub token", file: `fixtures/some/long/path/file-${i}.txt`, line: 1, commit: "a".repeat(40) }));
  assert.ok(keysComment("o/r", hits).length < 65_536);
  assert.match(keysComment("o/r", hits), /And 4900 more/);
  const r = repo();
  try {
    const db = openDb(":memory:");
    saveAgentSettings(db, { keys: true });
    const gh = fake([]);
    await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null });
    const sha = r.commit({ "a.ts": `export const k = "${GH}";\n` });
    withOrigin(r, sha);
    const open = fake([pr(r, sha)]);
    const github: GithubPort = { ...open.github, comment: async () => { throw new Error("HTTP 422"); } };
    assert.deepEqual(await pollAgents(db, ["o/r"], { github, repoPath: () => r.dir, baseUrl: null }), { checked: 1, failed: 1 });
    assert.equal(open.statuses.at(-1).state, "failure");
  } finally { r.cleanup(); }
});

// ---------------------------------------------------------------- what the third real review found

test("taking a secret file out isn't flagged, test fixtures aren't, and snake_case isn't a key", () => {
  assert.deepEqual(scanPatch("diff --git a/.env b/.env\ndeleted file mode 100644\n--- a/.env\n+++ /dev/null\n@@ -1 +0,0 @@\n-A=1\n"), []);
  assert.deepEqual(scanPatch("diff --git a/test/fixtures/.env b/test/fixtures/.env\nnew file mode 100644\n"), []);
  assert.equal(scanLine("re_authenticate_user_session_now()"), null);
  assert.equal(scanLine("re_" + "AbCdEf123456_ghIJklMNop"), "Resend API key");
});

test("the key watcher sees keys from a merge and in text git thinks is binary", async () => {
  const r = repo();
  try {
    const g = (...a: string[]) => execFileSync("git", a, { cwd: r.dir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    g("checkout", "-q", "-b", "pr");
    r.commit({ "a.ts": "export const a = 2;\n" });
    g("checkout", "-q", "main");
    r.commit({ "a.ts": "export const a = 3;\n" });
    const base = g("rev-parse", "HEAD");
    g("checkout", "-q", "pr");
    try { g("merge", "-q", "main"); } catch { /* the conflict is the point */ }
    writeFileSync(join(r.dir, "a.ts"), `export const k = "${GH}";\n`);
    g("add", "-A"); g("commit", "-qm", "merge");
    const merged = g("rev-parse", "HEAD");
    assert.equal((await checkKeys(r.dir, { baseSha: base, sha: merged })).length, 1);
    const bin = r.commit({ "b.txt": `\0${GH}\n` });
    assert.ok((await checkKeys(r.dir, { baseSha: merged, sha: bin })).some((h) => h.file === "b.txt"));
  } finally { r.cleanup(); }
});

test("fungi doesn't pass files it never read, and doesn't cry wolf on normal changes", async () => {
  const r = repo();
  try {
    const run = async (baseSha: string, sha: string, found: any[] = []) => checkDependencies(r.dir, { baseSha, sha }, async (list) => found.length ? found : (list.length ? [] : []));
    const req = r.commit({ "requirements.txt": "Django==2.0\n" });
    const asked: string[] = [];
    await checkDependencies(r.dir, { baseSha: r.base, sha: req }, async (list) => { asked.push(...list.map((p) => `${p.ecosystem}:${p.name}`)); return []; });
    assert.ok(asked.some((a) => a.startsWith("PyPI:") && a.toLowerCase().includes("django")));
    const pom = r.commit({ "pom.xml": "<project/>\n" });
    assert.deepEqual((await run(req, pom)).uncheckable, ["pom.xml"]);
    const toml = r.commit({ "Cargo.toml": "[package]\n" });
    assert.deepEqual((await run(pom, toml)).uncheckable, ["Cargo.toml"]);
    execFileSync("mkdir", ["-p", join(r.dir, "packages/a")]);
    const mono = r.commit({ "packages/a/package.json": "{}", "package-lock.json": lock({ old: "1.0.0", shared: "2.0.0", added: "1.0.0" }) });
    assert.deepEqual((await run(toml, mono)).uncheckable, [], "a lockfile above it counts");
    const go = r.commit({ "go.mod": "module x\n", "go.sum": "" });
    assert.deepEqual((await run(mono, go)).uncheckable, [], "go.sum with its go.mod");
  } finally { r.cleanup(); }
});

test("an advisory with no usable severity fails, and a fixed or closed PR leaves the flagged list", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    saveAgentSettings(db, { fungi: true });
    await pollAgents(db, ["o/r"], { github: fake([]).github, repoPath: () => r.dir, baseUrl: null });
    const bad = r.commit({ "package-lock.json": lock({ fresh: "1.0.0" }) });
    withOrigin(r, bad);
    const unknown = async () => [{ ecosystem: "npm", name: "fresh", version: "1.0.0", vulnId: "GHSA-1", severity: "UNKNOWN", summary: "x", fixed: null }];
    const open = [pr(r, bad)];
    const gh = fake(open);
    assert.deepEqual(await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null, check: unknown }), { checked: 1, failed: 1 });
    assert.equal(agentsView(db).problems.length, 1);
    open.length = 0;
    await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null, check: unknown });
    assert.equal(agentsView(db).problems.length, 0, "the PR closed");
    assert.equal(agentsView(db).totals.fungi.failed, 1, "but it still counts as flagged");
  } finally { r.cleanup(); }
});

test("each agent only runs on its chosen repos, and a repo turned off leaves the flagged list", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    saveAgentSettings(db, { keys: true, fungi: true });
    await pollAgents(db, ["o/r"], { github: fake([]).github, repoPath: () => r.dir, baseUrl: null });
    const sha = r.commit({ "a.ts": `export const k = "${GH}";\n` });
    withOrigin(r, sha);
    saveRepoChoices(db, { changes: [{ slug: "o/r", agent: "fungi", on: false }] }, ["o/r"]);
    const gh = fake([pr(r, sha)]);
    const deps: AgentDeps = { github: gh.github, repoPath: () => r.dir, baseUrl: null, check: async () => { throw new Error("fungi shouldn't run"); } };
    assert.deepEqual(await pollAgents(db, ["o/r"], deps), { checked: 1, failed: 1 });
    assert.deepEqual(gh.statuses.map((s) => s.context), ["Mycelium keys"]);
    assert.equal(agentsView(db).problems.length, 1);
    saveRepoChoices(db, { changes: [{ slug: "o/r", agent: "keys", on: false }] }, ["o/r"]);
    assert.equal(agentsView(db).problems.length, 0);
    const before = gh.statuses.length;
    let asked = 0;
    await pollAgents(db, ["o/r"], { ...deps, github: { ...gh.github, listOpenPrs: async () => { asked++; return { prs: [], answered: [], partial: [] }; } } });
    assert.equal(asked, 0, "with every agent off for every repo, GitHub isn't asked");
    assert.equal(gh.statuses.length, before);
  } finally { r.cleanup(); }
});

// ---------------------------------------------------------------- found on the first real run

test("a repo this account can't post to records its result once and stops retrying", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    saveAgentSettings(db, { keys: true });
    await pollAgents(db, ["o/r"], { github: fake([]).github, repoPath: () => r.dir, baseUrl: null });
    const sha = r.commit({ "a.ts": "export const a = 2;\n" });
    withOrigin(r, sha);
    const gh = fake([pr(r, sha)]);
    let posts = 0;
    const github: GithubPort = { ...gh.github, setStatus: async () => { posts++; throw Object.assign(new Error("Command failed"), { stderr: "gh: Not Found (HTTP 404)" }); } };
    const deps: AgentDeps = { github, repoPath: () => r.dir, baseUrl: null };
    assert.deepEqual(await pollAgents(db, ["o/r"], deps), { checked: 1, failed: 0 });
    await pollAgents(db, ["o/r"], deps);
    assert.equal(posts, 1, "no retry");
    assert.equal(gh.comments.length, 0);
    assert.match((db.prepare("SELECT note FROM agent_checks").get() as any).note, /can't post/);
    const other: GithubPort = { ...gh.github, setStatus: async () => { throw Object.assign(new Error("Command failed"), { stderr: "gh: Server Error (HTTP 502)" }); } };
    const next = r.commit({ "a.ts": "export const a = 3;\n" });
    execFileSync("git", ["update-ref", "refs/pull/1/head", next], { cwd: r.dir, stdio: "ignore" });
    const moved: GithubPort = { ...other, listOpenPrs: async () => ({ prs: [pr(r, next, { baseSha: sha })], answered: ["o/r"], partial: [] }) };
    await assert.rejects(pollAgents(db, ["o/r"], { ...deps, github: moved }), /Command failed/);
    assert.equal((db.prepare("SELECT count(*) AS n FROM agent_checks WHERE sha = ?").get(next) as any).n, 0, "a passing outage is retried");
  } finally { r.cleanup(); }
});

test("an agent switched on during a pass still leaves open PRs alone", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    saveAgentSettings(db, { keys: true });
    const sha = r.commit({ "package-lock.json": lock({ fresh: "1.0.0" }) });
    withOrigin(r, sha);
    const gh = fake([pr(r, sha)]);
    const github: GithubPort = { ...gh.github, listOpenPrs: async (repos) => { saveAgentSettings(db, { fungi: true }); return gh.github.listOpenPrs(repos); } };
    await pollAgents(db, ["o/r"], { github, repoPath: () => r.dir, baseUrl: null });
    let ran = 0;
    const check = async () => { ran++; return []; };
    await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null, check });
    assert.equal(ran, 0, "the PR was already open, so fungi waits for it to change");
    assert.equal((db.prepare("SELECT state FROM agent_checks WHERE agent = 'fungi'").get() as any).state, "skipped");
  } finally { r.cleanup(); }
});


test("settings: Crimson and a11y save, re-baseline when toggled, and old records gain their seen lists", () => {
  const db = openDb(":memory:");
  const s1 = saveAgentSettings(db, { crimson: true, a11y: true });
  assert.equal(s1.crimson, true);
  assert.equal(s1.a11y, true);
  assert.deepEqual(s1.seen.crimson, []);
  // Pretend a poll recorded that o/r has been seen by crimson.
  db.prepare("UPDATE settings SET value = ? WHERE key = 'agents'").run(JSON.stringify({ ...s1, seen: { ...s1.seen, crimson: ["o/r"] } }));
  // Turning it off and on again clears that, so its open PRs wait instead of flagging a backlog.
  saveAgentSettings(db, { crimson: false });
  const s2 = saveAgentSettings(db, { crimson: true });
  assert.deepEqual(s2.seen.crimson, []);
  // A record written before a11y existed still loads with an a11y seen list.
  db.prepare("UPDATE settings SET value = ? WHERE key = 'agents'").run(JSON.stringify({ keys: true, fungi: false, fungiAutoFix: false, seen: { keys: [], fungi: [] } }));
  assert.deepEqual(loadAgentSettings(db).seen.a11y, []);
});

test("Crimson blocks on a high finding; a11y is advisory; both count against the shared budget", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    const engine: ReviewEngine = async (_input, _repo, _sha, system) => {
      const crimson = /red-team/.test(system ?? "");
      return { result: { summary: crimson ? "a backdoor" : "a missing label",
        findings: [{ severity: "high", category: crimson ? "security" : "a11y", file: "a.ts", line: 1, title: crimson ? "backdoor" : "no label", detail: "d", suggestion: "s" }] }, costUsd: null };
    };
    saveAgentSettings(db, { crimson: true, a11y: true });
    const first = r.commit({ "a.ts": "export const a = 2;\n" });
    const open = [pr(r, first, { author: "alice" })];
    const gh = fake(open);
    const deps: AgentDeps = { github: gh.github, repoPath: () => r.dir, baseUrl: null, engine };
    withOrigin(r, first);
    await pollAgents(db, ["o/r"], deps); // PRs already open are baselined, not reviewed
    assert.equal(gh.statuses.length, 0);

    const next = r.commit({ "a.ts": "export const a = 3;\n" });
    execFileSync("git", ["update-ref", "refs/pull/1/head", next], { cwd: r.dir, stdio: "ignore" });
    open[0] = pr(r, next, { baseSha: first, author: "alice" });
    await pollAgents(db, ["o/r"], deps);
    const last = (c: string) => gh.statuses.filter((s) => s.context === c).at(-1);
    assert.equal(last("Mycelium crimson")!.state, "failure", "a high red-team finding blocks");
    assert.equal(last("Mycelium a11y")!.state, "success", "a11y is advisory and never blocks");
    assert.equal((db.prepare("SELECT count(*) AS n FROM review_runs").get() as { n: number }).n, 2, "each lens run counts against the daily budget");
    assert.ok(gh.comments.some((c) => /Mycelium crimson/.test(c.body)) && gh.comments.some((c) => /advisory/.test(c.body)));
  } finally {
    r.cleanup();
  }
});

test("AI lenses need an engine, and skip forks and dependency bots", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    let called = 0;
    const engine: ReviewEngine = async () => { called++; return { result: { summary: "", findings: [] }, costUsd: null }; };
    saveAgentSettings(db, { crimson: true });
    const first = r.commit({ "a.ts": "export const a = 2;\n" });
    withOrigin(r, first);
    // No engine: the lens is disabled, so nothing is even listed.
    assert.deepEqual(await pollAgents(db, ["o/r"], { github: fake([pr(r, first)]).github, repoPath: () => r.dir, baseUrl: null }), { checked: 0, failed: 0 });
    // With an engine: baseline the already-open PR, then a dependency-bot PR is skipped without calling the engine.
    await pollAgents(db, ["o/r"], { github: fake([pr(r, first)]).github, repoPath: () => r.dir, baseUrl: null, engine });
    const next = r.commit({ "a.ts": "export const a = 3;\n" });
    execFileSync("git", ["update-ref", "refs/pull/1/head", next], { cwd: r.dir, stdio: "ignore" });
    const gh = fake([pr(r, next, { baseSha: first, author: "dependabot[bot]" })]);
    await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null, engine });
    assert.equal(called, 0, "the engine never ran for a dependency-bot PR");
    assert.equal(gh.statuses.length, 0, "a skipped PR posts no check");
  } finally {
    r.cleanup();
  }
});

const seeChrimsonSeen = (db: any, repo = "o/r") => {
  const cur = JSON.parse((db.prepare("SELECT value FROM settings WHERE key='agents'").get() as any).value);
  db.prepare("UPDATE settings SET value=? WHERE key='agents'").run(JSON.stringify({ ...cur, seen: { ...cur.seen, crimson: [repo], a11y: [repo] } }));
};

test("a transient engine error retries, counts against the budget, then fails closed after the cap", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    let calls = 0;
    const engine: ReviewEngine = async () => { calls++; throw new Error("network blip"); };
    saveAgentSettings(db, { crimson: true });
    seeChrimsonSeen(db);
    const sha = r.commit({ "a.ts": "export const a = 2;\n" });
    withOrigin(r, sha);
    const open = [pr(r, sha, { baseSha: r.base, author: "alice" })];
    const deps: AgentDeps = { github: fake(open).github, repoPath: () => r.dir, baseUrl: null, engine };
    let last: any;
    for (let i = 0; i < 3; i++) { const gh = fake(open); await pollAgents(db, ["o/r"], { ...deps, github: gh.github }); last = gh; }
    assert.equal(calls, 3, "it retried up to the cap");
    assert.equal((db.prepare("SELECT count(*) AS n FROM review_runs").get() as any).n, 3, "each attempt counts against the shared budget");
    const row = db.prepare("SELECT state FROM agent_checks WHERE agent='crimson'").get() as any;
    assert.equal(row.state, "failed", "after the cap it fails closed, not silently");
    assert.equal(last.statuses.at(-1).state, "failure");
  } finally { r.cleanup(); }
});

test("engine trouble refunds the run and stops the pass (so the caller can pause)", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    const engine: ReviewEngine = async () => { throw new EngineTrouble("Your Claude plan's usage limit was reached."); };
    saveAgentSettings(db, { crimson: true });
    seeChrimsonSeen(db);
    const sha = r.commit({ "a.ts": "export const a = 2;\n" });
    withOrigin(r, sha);
    const gh = fake([pr(r, sha, { baseSha: r.base, author: "alice" })]);
    await assert.rejects(pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null, engine }), /usage limit/);
    assert.equal((db.prepare("SELECT count(*) AS n FROM review_runs").get() as any).n, 0, "an outage doesn't burn the budget");
    assert.equal(gh.statuses.length, 0, "nothing is posted");
  } finally { r.cleanup(); }
});

test("a non-blocking Crimson finding reads as notes for a person, not a pass", async () => {
  const r = repo();
  try {
    const db = openDb(":memory:");
    const engine: ReviewEngine = async () => ({ result: { summary: "one medium smell", findings: [{ severity: "medium", category: "obfuscation", file: "a.ts", line: 1, title: "base64 eval", detail: "d", suggestion: "s" }] }, costUsd: null });
    saveAgentSettings(db, { crimson: true });
    seeChrimsonSeen(db);
    const sha = r.commit({ "a.ts": "export const a = 2;\n" });
    withOrigin(r, sha);
    const gh = fake([pr(r, sha, { baseSha: r.base, author: "alice" })]);
    await pollAgents(db, ["o/r"], { github: gh.github, repoPath: () => r.dir, baseUrl: null, engine });
    const st = gh.statuses.find((s: any) => s.context === "Mycelium crimson");
    assert.equal(st.state, "success", "a medium finding doesn't block");
    assert.match(st.description, /note/, "but it's not reported as 'nothing suspicious'");
  } finally { r.cleanup(); }
});
