import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { companyName, openDb, saveCompanyName } from "../src/db.ts";
import { applyAutoWatch, fetchRepos, loadAutoWatch, loadHiddenAccounts, loadRepoIssues, newRepos, parseRepoInput, planRepoChange, saveAutoWatch, saveHiddenAccounts, updateRepoIssues, validSlug, writeRepoList, type GithubRepo, agentOnFor, loadRepoChoices, saveRepoChoices, repoChoicesView } from "../src/repos.ts";
import { readRepoList } from "../src/sync.ts";

const repo = (slug: string, over: Partial<GithubRepo> = {}): GithubRepo => ({ slug, owner: slug.split("/")[0], private: false, archived: false, fork: false, description: "", pushedAt: null, ...over });

test("removing a repo ignores its clone, and adding it back undoes that", () => {
  const out = planRepoChange("/c", ["o/a", "o/b"], ["/other"], [], ["o/b"]);
  assert.deepEqual(out.list, ["o/a"]);
  assert.deepEqual(out.ignored, ["/other", "/c/b"]);
  const back = planRepoChange("/c", out.list, out.ignored, ["o/b"], []);
  assert.deepEqual(back.list.sort(), ["o/a", "o/b"]);
  assert.deepEqual(back.ignored, ["/other"]);
});

test("same-named repos from two owners use the folder the clone is really in", () => {
  const out = planRepoChange("/c", ["x/app", "y/app"], [], [], ["y/app"]);
  assert.deepEqual(out.ignored, ["/c/y__app"]);
});

test("removing something that isn't watched changes nothing", () => {
  assert.deepEqual(planRepoChange("/c", ["o/a"], [], [], ["o/zzz"]), { list: ["o/a"], ignored: [] });
});

test("repo names that could become git or gh flags are refused", () => {
  for (const bad of ["--upload-pack=x/y", "-x/y", "o/../../etc", "o", "o/a/b", "o/a b", "", null, 5]) assert.equal(validSlug(bad), false, String(bad));
  assert.equal(validSlug("Owner-1/repo.name_2"), true);
});

test("auto-watch adds only new repos: turning it on doesn't pull in existing ones, and unticked stays unticked", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mycelium-repos-"));
  try {
    const file = join(dir, "repos.txt");
    writeRepoList(file, ["o/a"]);
    const db = openDb(":memory:");
    const existing = [repo("o/a"), repo("o/unticked"), repo("other/x")];
    saveAutoWatch(db, ["o"], existing);
    assert.deepEqual(await applyAutoWatch(db, dir, file, readRepoList(file), async () => existing), []);

    const later = [...existing, repo("o/new"), repo("o/old", { archived: true }), repo("other/y")];
    assert.deepEqual(await applyAutoWatch(db, dir, file, readRepoList(file), async () => later), ["o/new"]);
    assert.deepEqual(readRepoList(file), ["o/a", "o/new"]);

    // Added once. If someone then unticks it, the next run leaves it off.
    writeFileSync(file, "o/a\n");
    assert.deepEqual(await applyAutoWatch(db, dir, file, readRepoList(file), async () => later), []);
    assert.equal(readFileSync(file, "utf8"), "o/a\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("no owners means no call to GitHub", async () => {
  const db = openDb(":memory:");
  assert.deepEqual(await applyAutoWatch(db, "/c", "/nope", [], async () => { throw new Error("shouldn't be called"); }), []);
  assert.deepEqual(newRepos([repo("o/a")], { owners: [], seen: [] }), []);
});

test("pasted repos: names and URLs in any separator, junk reported, duplicates merged", () => {
  const out = parseRepoInput(`acme/api, https://github.com/acme/web.git
    git@github.com:acme/ssh.git https://github.com/acme/api/tree/main  https://github.com/acme/slash/
    --upload-pack=evil just-a-word https://gitlab.com/acme/other`);
  assert.deepEqual(out.slugs, ["acme/api", "acme/web", "acme/ssh", "acme/slash"]);
  assert.deepEqual(out.invalid, ["--upload-pack=evil", "just-a-word", "https://gitlab.com/acme/other"]);
  assert.deepEqual(parseRepoInput(""), { slugs: [], invalid: [] });
});

test("fetching: clones what's missing, pulls what's there, and one failure doesn't stop the rest", async () => {
  const calls: string[][] = [];
  const events: string[] = [];
  const out = await fetchRepos("/c", ["o/have"], ["o/have", "o/new", "o/bad"], (p) => events.push(`${p.slug}:${p.state}`), {
    exists: (p) => p === "/c/have/.git",
    run: async (cmd, args) => {
      calls.push([cmd, ...args]);
      if (args.includes("o/bad")) throw Object.assign(new Error("Command failed"), { stderr: "fatal: https://user:s3cret@github.com/o/bad not found\nmore" });
    },
  });
  assert.deepEqual(calls.find((c) => c[0] === "git"), ["git", "-C", "/c/have", "pull", "--ff-only", "--quiet"]);
  assert.deepEqual(calls.find((c) => c.includes("o/new")), ["gh", "repo", "clone", "o/new", "/c/new", "--", "--quiet"]);
  assert.equal(out.failed.length, 1);
  assert.equal(out.failed[0].slug, "o/bad");
  assert.doesNotMatch(out.failed[0].error, /s3cret/, "a token in a URL never reaches the page");
  assert.ok(events.includes("o/new:ok") && events.includes("o/bad:failed"));
  assert.equal(out.pathOf("o/new"), "/c/new");
});

test("fetching never runs more than the limit at once", async () => {
  let now = 0, peak = 0;
  await fetchRepos("/c", [], ["o/a", "o/b", "o/c", "o/d", "o/e"], () => {}, {
    exists: () => false, concurrency: 2,
    run: async () => { peak = Math.max(peak, ++now); await new Promise((r) => setTimeout(r, 5)); now--; },
  });
  assert.equal(peak, 2);
});

test("problems clear once a repo updates, and stay separate per repo", () => {
  const db = openDb(":memory:");
  updateRepoIssues(db, [], [{ slug: "o/a", error: "gone" }, { slug: "o/b", error: "denied" }]);
  updateRepoIssues(db, ["o/a"], []);
  assert.deepEqual(Object.keys(loadRepoIssues(db)), ["o/b"]);
});

test("the company name is cleaned and limited", () => {
  const db = openDb(":memory:");
  assert.equal(companyName(db), "");
  assert.equal(saveCompanyName(db, "  Acme\r\nBcc: x@y.z "), "Acme Bcc: x@y.z");
  assert.equal(companyName(db), "Acme Bcc: x@y.z");
  assert.throws(() => saveCompanyName(db, "x".repeat(81)), /80 characters/);
});

test("hiding an account stops auto-watching it, and bad names are refused", () => {
  const db = openDb(":memory:");
  saveAutoWatch(db, ["old", "keep"], [repo("old/a"), repo("keep/b")]);
  assert.deepEqual(saveHiddenAccounts(db, ["old", "old"]), ["old"]);
  assert.deepEqual(loadHiddenAccounts(db), ["old"]);
  assert.deepEqual(loadAutoWatch(db).owners, ["keep"]);
  assert.deepEqual(loadAutoWatch(db).seen, ["old/a", "keep/b"], "what's been seen is kept, so unhiding doesn't pull in old repos");
  assert.throws(() => saveHiddenAccounts(db, ["../etc"]), /account name/);
  assert.deepEqual(saveHiddenAccounts(db, []), []);
});

test("agents can be chosen per repo, and later repos follow their own setting", () => {
  const db = openDb(":memory:");
  assert.equal(agentOnFor(loadRepoChoices(db), "o/a", "review"), true, "on everywhere until narrowed");
  saveRepoChoices(db, { changes: [{ slug: "o/a", agent: "review", on: false }] }, ["o/a", "o/b"]);
  let c = loadRepoChoices(db);
  assert.equal(agentOnFor(c, "o/a", "review"), false);
  assert.equal(agentOnFor(c, "o/a", "keys"), true);
  assert.equal(agentOnFor(c, "o/b", "review"), true);
  saveRepoChoices(db, { newRepos: false }, ["o/a", "o/b"]);
  c = loadRepoChoices(db);
  assert.equal(agentOnFor(c, "o/b", "review"), true, "repos already listed don't flip");
  assert.equal(agentOnFor(c, "o/a", "review"), false);
  assert.equal(agentOnFor(c, "o/later", "review"), false, "later ones follow the new answer");
  assert.throws(() => saveRepoChoices(db, { changes: [{ slug: "x/y", agent: "keys", on: true }] }, ["o/a"]), /isn't being watched/);
  assert.throws(() => saveRepoChoices(db, { changes: [{ slug: "o/a", agent: "nope", on: true }] }, ["o/a"]), /no agent/);
  assert.throws(() => saveRepoChoices(db, { changes: [{ slug: "o/a", agent: "keys", on: "yes" }] }, ["o/a"]), /on or off/);
  assert.deepEqual(repoChoicesView(db, ["o/a"]).repos, [{ slug: "o/a", review: false, keys: true, fungi: true, janitor: true, crimson: true, a11y: true }]);
});
