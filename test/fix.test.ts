import { test } from "node:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { errLine, ignoredOverrides, npmLockHas, plainOverrideSafe, prBody, prTitle, siblingSource, type FixPlan, type PlannedFix } from "../src/fix.ts";

const fx = (over: Partial<PlannedFix>): PlannedFix => ({
  project: "app", projectPath: "/r/app", component: "package-lock.json", ecosystem: "npm", name: "next", from: "16.1.1",
  to: "16.4.1", direct: true, severity: "CRITICAL", vulns: ["GHSA-2464-fhr4-w9xw", "CVE-2026-75604"], breaking: false,
  strategy: "bump-direct", note: "", ...over,
});

test("PR body: fixed table with advisory links, leftovers, verification", () => {
  const plan: FixPlan = { project: "app", projectPath: "/r/app", fixes: [] };
  const zip = fx({ name: "zip", ecosystem: "crates.io", from: "4.6.1", to: "9.0.5", strategy: "manual", severity: "CRITICAL" });
  const body = prBody(plan, {
    applied: [fx({}), fx({ name: "tmp", from: "0.2.5", to: "0.2.6", severity: "HIGH", vulns: ["GHSA-x"] })],
    stillVulnerable: ["tmp@0.2.5 (package-lock.json)"],
    skipped: [{ fix: zip, reason: "a parent crate pins zip to 4.x" }],
    failed: [],
    verify: [{ dir: "/r/app", command: "npm run build", ok: true, output: "" }],
  });
  assert.match(body, /\| CRITICAL \| `next` \| 16\.1\.1 → 16\.4\.1/);
  assert.match(body, /\[GHSA-2464-fhr4-w9xw\]\(https:\/\/github\.com\/advisories\/GHSA-2464-fhr4-w9xw\)/);
  assert.match(body, /\[CVE-2026-75604\]\(https:\/\/nvd\.nist\.gov/);
  assert.doesNotMatch(body, /\| HIGH \| `tmp`/, "still-vulnerable packages aren't listed as fixed");
  assert.match(body, /`tmp@0\.2\.5 \(package-lock\.json\)`: the package manager kept the old version/);
  assert.match(body, /`zip` 4\.6\.1: a parent crate pins zip to 4\.x/);
  assert.match(body, /✅ `npm run build`/);
  assert.match(body, /never merges/);
});

test("isPrerelease: betas and RCs are not shippable fixes", async () => {
  const { isPrerelease } = await import("../src/fix.ts");
  for (const v of ["2.4.20-Beta1", "1.0.0-rc.1", "3.0.0-alpha", "5.0.0-M2", "1.2.0-SNAPSHOT", "16.0.0-canary.3", "2.0.0b1", "1.0rc2"]) assert.ok(isPrerelease(v), v);
  for (const v of ["2.4.20", "0.8.3", "1.0.11", "2.0.119", "4.17.21", "1.2.3-1", "2024.1.0"]) assert.ok(!isPrerelease(v), v);
});

test("errLine: keeps the reason, not just the 'failed:' headline", () => {
  const npm = [
    "npm install --package-lock-only --ignore-scripts failed:",
    "npm warn ERESOLVE overriding peer dependency",
    "npm error code ERESOLVE",
    "npm error ERESOLVE could not resolve",
    "npm error Conflicting peer dependency: @angular/core@21.2.26",
  ].join("\n");
  assert.equal(errLine(npm), "npm install --package-lock-only --ignore-scripts failed: Conflicting peer dependency: @angular/core@21.2.26");
  const push = "git push failed:\nremote: Permission to org/repo.git denied to someone.\nfatal: unable to access 'https://github.com/org/repo.git/': The requested URL returned error: 403";
  assert.equal(errLine(push), "git push failed: Permission to org/repo.git denied to someone.");
  assert.equal(errLine("one line only"), "one line only");
  assert.equal(errLine("pnpm install failed:\n ERR_PNPM_OUTDATED_LOCKFILE  Cannot install"), "pnpm install failed: ERR_PNPM_OUTDATED_LOCKFILE  Cannot install");
});

test("cargoDependents: registry parents of a pinned crate, bare names resolved, path crates skipped", async () => {
  const { cargoDependents } = await import("../src/fix.ts");
  const lock = `version = 4

[[package]]
name = "tallybook"
version = "0.2.0"
dependencies = [
 "tauri-plugin-updater",
]

[[package]]
name = "tauri-plugin-updater"
version = "2.14.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "zip 4.6.1",
 "serde",
]

[[package]]
name = "plist"
version = "1.8.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "quick-xml",
]

[[package]]
name = "quick-xml"
version = "0.38.4"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "zip"
version = "4.6.1"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "zip"
version = "9.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`;
  assert.deepEqual(cargoDependents(lock, ["zip@4.6.1"]), ["tauri-plugin-updater@2.14.0"]);
  assert.deepEqual(cargoDependents(lock, ["quick-xml@0.38.4"]), ["plist@1.8.0"], "bare dep name = the only locked version");
  assert.deepEqual(cargoDependents(lock, ["tauri-plugin-updater@2.14.0"]), [], "workspace crates aren't cargo-updatable");
});

test("unlockNpm: drops top-level and nested entries of the named packages only", async () => {
  const { mkdtempSync, writeFileSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { unlockNpm } = await import("../src/fix.ts");
  const p = join(mkdtempSync(join(tmpdir(), "myc-test-")), "package-lock.json");
  writeFileSync(p, JSON.stringify({ lockfileVersion: 3, packages: {
    "": { name: "x" },
    "node_modules/@angular/core": { version: "21.2.5" },
    "node_modules/@angular/forms": { version: "21.2.5" },
    "node_modules/@angular/cli": { version: "21.2.3" },
    "node_modules/readdir-glob/node_modules/minimatch": { version: "5.1.9" },
    "node_modules/minimatch": { version: "11.0.4" },
    "node_modules/minimatch-extra": { version: "1.0.0" },
  } }, null, 2));
  unlockNpm(p, ["@angular/core", "@angular/forms", "minimatch"]);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(p, "utf8")).packages), ["", "node_modules/@angular/cli", "node_modules/minimatch-extra"]);
});

test("mergeRoots: scanning a folder adds to the remembered roots, never narrows them", async () => {
  const { mergeRoots } = await import("../src/scan.ts");
  const C = "/Users/me/Companies";
  assert.deepEqual(mergeRoots([`${C}/werbosLLM`], [C]), [`${C}/werbosLLM`, C], "both kept: the nested root finds werbosLLM's own projects");
  assert.deepEqual(mergeRoots([C], [C]), [C]);
  assert.deepEqual(mergeRoots([], ["/a"]), ["/a"]);
});

test("ignored folders are left out of a scan, including when nested inside a project", async () => {
  const { mkdtempSync, mkdirSync, writeFileSync, realpathSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { findProjects, scanProject, setIgnored } = await import("../src/scan.ts");
  const root = realpathSync(mkdtempSync(join(tmpdir(), "myc-ignore-")));
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "x" }, "node_modules/left-pad": { version: "1.0.0" } } });
  for (const d of ["real", "snap"]) {
    mkdirSync(join(root, d));
    writeFileSync(join(root, d, "package.json"), JSON.stringify({ name: d }));
    writeFileSync(join(root, d, "package-lock.json"), lock);
  }
  setIgnored([join(root, "snap")]);
  try {
    assert.deepEqual(findProjects(root), [join(root, "real")], "not discovered as a project");
    assert.deepEqual(scanProject(root).components.map((c) => c.path), ["real/package-lock.json"], "not walked inside a parent");
  } finally {
    setIgnored([]);
  }
});

test("pnpmLockHas: matches an exact lock entry, not a similar one", async () => {
  const { pnpmLockHas } = await import("../src/fix.ts");
  const lock = "packages:\n\n  vite@7.3.0:\n    resolution: {}\n  '@scope/pkg@1.2.3':\n    resolution: {}\nsnapshots:\n\n  rollup@4.1.0(foo@1.0.0):\n    dependencies: {}\n";
  assert.ok(pnpmLockHas(lock, "vite", "7.3.0"));
  assert.ok(pnpmLockHas(lock, "@scope/pkg", "1.2.3"));
  assert.ok(pnpmLockHas(lock, "rollup", "4.1.0"), "snapshot key with peers");
  assert.ok(!pnpmLockHas(lock, "vite", "7.3.7"));
  assert.ok(!pnpmLockHas(lock, "foo", "1.0.0"), "a peer in parentheses isn't an entry");
});

test("acceptance: narrow on purpose (project, advisory, expiry), never for malicious packages", async () => {
  const { acceptanceCovers } = await import("../src/graph.ts");
  const now = new Date("2026-06-01");
  const rule = {
    name: "glib", vulnIds: ["RUSTSEC-1"], projects: ["app"], reason: "r",
    acceptedAt: "2026-05-01T00:00:00Z", expires: "2026-08-01T00:00:00Z",
  };
  const f = { name: "glib", version: "0.18.5", vulnId: "RUSTSEC-1" };
  assert.ok(acceptanceCovers(rule, f, "app", now));
  assert.ok(!acceptanceCovers(rule, f, "other", now), "another project stays open");
  assert.ok(!acceptanceCovers(rule, { ...f, vulnId: "RUSTSEC-2" }, "app", now), "a new advisory stays open");
  assert.ok(!acceptanceCovers(rule, { ...f, name: "gtk" }, "app", now));
  assert.ok(!acceptanceCovers(rule, f, "app", new Date("2026-09-01")), "expired acceptances stop applying");
  assert.ok(acceptanceCovers(rule, { ...f, version: "0.19.0" }, "app", now), "no version pin: same advisory, any version");
  assert.ok(!acceptanceCovers({ ...rule, version: "0.18.5" }, { ...f, version: "0.19.0" }, "app", now), "version pin holds");
  assert.ok(!acceptanceCovers({ ...rule, vulnIds: ["MAL-1"] }, { ...f, vulnId: "MAL-1" }, "app", now), "malicious is never covered");
});

test("dashboard: engine log lines map to pipeline steps, and status reads open before accepted", async () => {
  const { stepOf, statusOf } = await import("../src/dashboard.ts");
  assert.equal(stepOf("PR mode: building on origin/main"), "pull");
  assert.equal(stepOf("working in a separate worktree on mycelium/fix-1 (from origin/main); your checkout is untouched"), "branch");
  assert.equal(stepOf("edited /tmp/x/package.json"), "fix");
  assert.equal(stepOf("npm: lockfile updated in /tmp/x"), "fix");
  assert.equal(stepOf("cargo-parent: zip 2 → 9"), "fix");
  assert.equal(stepOf("✓ npm run build"), "verify");
  assert.equal(stepOf("≈ npm test (fails the same way on origin/main: pre-existing, not caused by this fix)"), "verify");
  assert.equal(stepOf("checking whether `npm test` already fails on origin/main…"), "verify");
  assert.equal(stepOf("committed on mycelium/fix-1"), "commit");
  assert.equal(stepOf("pushed mycelium/fix-1"), "push");
  assert.equal(stepOf("opened PR https://github.com/a/b/pull/1 → main"), "pr");
  assert.equal(stepOf("something else entirely"), null);
  assert.equal(statusOf(2, 1), "attention");
  assert.equal(statusOf(0, 1), "accepted");
  assert.equal(statusOf(0, 0), "clean");
});

test("reposIn: finds a repo, or the repos nested in a folder that isn't one", async () => {
  const { mkdtempSync, mkdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { reposIn } = await import("../src/dashboard.ts");
  const root = mkdtempSync(join(tmpdir(), "myc-repos-"));
  for (const d of ["a/.git", "b/inner/.git", "b/inner/nested/.git", "node_modules/x/.git", ".hidden/.git", "c/empty"]) mkdirSync(join(root, d), { recursive: true });
  assert.deepEqual(reposIn(root).sort(), [join(root, "a"), join(root, "b/inner")].sort(), "stops at a repo; skips node_modules and dot folders");
  assert.deepEqual(reposIn(join(root, "a")), [join(root, "a")]);
  assert.deepEqual(reposIn(join(root, "c")), []);
});

test("downgrade hint: range checks and candidate picking stay conservative", async () => {
  const { rangeAllows, pickCandidate, declaredRanges, parseVersion } = await import("../src/downgrade.ts");
  assert.equal(rangeAllows("^4.2.2", "4.1.2"), false, "a parent needing 4.2.2 rejects 4.1.2");
  assert.equal(rangeAllows("^4.2.2", "4.9.0"), true);
  assert.equal(rangeAllows("^4.2.2", "5.0.0"), false);
  assert.equal(rangeAllows("^0.3.1", "0.3.9"), true);
  assert.equal(rangeAllows("^0.3.1", "0.4.0"), false);
  assert.equal(rangeAllows("~1.2.3", "1.2.9"), true);
  assert.equal(rangeAllows("~1.2.3", "1.3.0"), false);
  assert.equal(rangeAllows(">=1.0.0 <2.0.0", "1.5.0"), true);
  assert.equal(rangeAllows(">=1.0.0 <2.0.0", "2.0.0"), false);
  assert.equal(rangeAllows("^1.0.0 || ^2.0.0", "2.1.0"), true);
  assert.equal(rangeAllows("1.x", "1.9.0"), true);
  assert.equal(rangeAllows("*", "1.0.0"), true);
  assert.equal(rangeAllows("4.1.2", "4.1.2"), true);
  assert.equal(rangeAllows("github:a/b", "1.0.0"), null, "a form we can't read is not a yes");
  assert.equal(rangeAllows("1.0.0 - 2.0.0", "1.5.0"), null);
  assert.equal(parseVersion("1.0.0-beta.1"), null);

  const versions = ["4.0.0", "4.1.0", "4.1.2", "4.2.0", "4.3.1", "4.1.3-beta.1"];
  assert.equal(pickCandidate(versions, ["4.2.0"]), "4.1.2", "newest stable below the introduction");
  assert.equal(pickCandidate(versions, ["4.2.0", "4.1.0"]), "4.0.0", "below the earliest advisory");
  assert.equal(pickCandidate(versions, ["0"]), null, "from the start: nothing older is clean");
  assert.equal(pickCandidate(versions, ["0.0.0-0"]), null);
  assert.equal(pickCandidate(versions, ["4.2.0", "0"]), null);
  assert.equal(pickCandidate(versions, ["4.0.0"]), null, "nothing older exists");
  assert.equal(pickCandidate(versions, []), null);

  const lock = JSON.stringify({ packages: { "": { dependencies: { a: "^1.0.0" } }, "node_modules/b": { dependencies: { a: "^1.2.0" } }, "node_modules/c": { peerDependencies: { a: "*" } } } });
  assert.deepEqual(declaredRanges(lock, "a").sort(), ["*", "^1.0.0", "^1.2.0"]);
});

test("sync: reads GitHub remotes without keeping credentials, and folder names don't collide", async () => {
  const { githubSlug, cloneDirs } = await import("../src/sync.ts");
  assert.equal(githubSlug("https://github.com/a/b.git"), "a/b");
  assert.equal(githubSlug("git@github.com:a/b.git"), "a/b");
  assert.equal(githubSlug("https://github.com/a/b"), "a/b");
  assert.equal(githubSlug("https://x:ghp_secret@github.com/a/b.git"), "a/b", "an embedded token never comes through");
  assert.equal(githubSlug("https://gitlab.com/a/b.git"), null);
  assert.deepEqual([...cloneDirs(["a/one", "b/two"]).values()], ["one", "two"]);
  assert.deepEqual([...cloneDirs(["a/same", "b/Same"]).values()], ["a__same", "b__Same"]);
});

test("npmLockHas finds nested copies and only exact versions", () => {
  const lock = JSON.stringify({ packages: { "": {}, "node_modules/a": { version: "2.0.0" }, "node_modules/b/node_modules/a": { version: "1.0.0" }, "node_modules/x-a": { version: "1.0.0" } } });
  assert.equal(npmLockHas(lock, "a", "1.0.0"), true);
  assert.equal(npmLockHas(lock, "a", "3.0.0"), false);
  assert.equal(npmLockHas("not json", "a", "1.0.0"), false);
});

test("an override npm ignored is reported; a bump that left a nested copy isn't an override", () => {
  const lock = JSON.stringify({ packages: { "node_modules/core": { version: "2.0.0" }, "node_modules/p/node_modules/core": { version: "1.0.0" } } });
  const stuck = fx({ name: "core", from: "1.0.0", strategy: "override" });
  assert.deepEqual(ignoredOverrides(lock, [stuck, fx({ name: "core", from: "1.0.0", strategy: "bump-direct" }), fx({ name: "gone", from: "1.0.0", strategy: "override" })]), [stuck]);
});

test("PR title counts what was fixed, not what was attempted", () => {
  const zod = fx({ name: "zod", from: "3.25.76", severity: "HIGH" });
  const ftp = fx({ name: "basic-ftp", from: "5.3.1", severity: "CRITICAL" });
  assert.equal(prTitle([zod, ftp], ["basic-ftp@5.3.1 (package-lock.json)"]), "Mycelium: upgrade 1 vulnerable package (high: zod)");
  assert.equal(prTitle([zod, ftp], []), "Mycelium: upgrade 2 vulnerable packages (critical: basic-ftp)");
});

test("a plain override is only safe when no copy sits on another major", () => {
  const lock = (...v: string[]) => JSON.stringify({ packages: Object.fromEntries(v.map((x, i) => [`node_modules/p${i}/node_modules/core`, { version: x }])) });
  const f = fx({ name: "core", from: "1.30.1", to: "2.8.0", strategy: "override" });
  assert.equal(plainOverrideSafe(lock("1.30.1", "2.12.0"), f), true);
  assert.equal(plainOverrideSafe(lock("1.30.1", "3.0.0"), f), false);
  assert.equal(plainOverrideSafe("not json", f), false);
});

test("a sibling path matches its folder whatever the case, but never guesses", () => {
  const dir = mkdtempSync(join(tmpdir(), "mycelium-sib-"));
  mkdirSync(join(dir, "veilchain"));
  mkdirSync(join(dir, "Exact"));
  try {
    const exact = existsSync(join(dir, "EXACT")); // a Mac's filesystem already matches this, so there's nothing to resolve
    assert.equal(siblingSource(join(dir, "Exact")), join(dir, "Exact"));
    if (!exact) assert.equal(siblingSource(join(dir, "VeilChain")), join(dir, "veilchain"));
    mkdirSync(join(dir, "veilchain", "core"));
    if (!exact) assert.equal(siblingSource(join(dir, "VeilChain", "core")), join(dir, "veilchain", "core"));
    assert.equal(siblingSource(join(dir, "nothere")), join(dir, "nothere"));
    assert.equal(siblingSource(join(dir, "gone", "x")), join(dir, "gone", "x"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
