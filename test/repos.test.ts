import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { openDb } from "../src/db.ts";
import { applyAutoWatch, newRepos, planRepoChange, saveAutoWatch, validSlug, writeRepoList, type GithubRepo } from "../src/repos.ts";
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
