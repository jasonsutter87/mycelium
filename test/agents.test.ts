import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentsView, checkDependencies, checkKeys, fungiComment, keysComment, pollAgents, saveAgentSettings, type AgentDeps } from "../src/agents.ts";
import { openDb } from "../src/db.ts";
import { describeHits, redactKeys, scanLine, scanPatch } from "../src/keys.ts";
import type { GithubPort, OpenPr } from "../src/review.ts";

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
  assert.equal(scanLine("-----BEGIN RSA PRIVATE KEY-----"), "private key");
  assert.equal(scanLine("AKIAIOSFODNN7EXAMPLE"), null);
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
    assert.deepEqual(out.manifestOnly, []);
    assert.match(fungiComment(out), /fresh/);
    const lone = r.commit({ "package.json": '{"name":"x"}' });
    assert.deepEqual((await checkDependencies(r.dir, { baseSha: sha, sha: lone }, async () => [])).manifestOnly, ["package.json"]);
  } finally { r.cleanup(); }
});

test("advisory text can't ping people or inject markup", () => {
  const c = fungiComment({ manifestOnly: [], added: [{ ecosystem: "npm", name: "p", version: "1", vulnId: "GHSA-1", severity: "HIGH", summary: "hi @octocat <img src=x> ![a](b)", fixed: null, lockfile: "l" }] });
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
