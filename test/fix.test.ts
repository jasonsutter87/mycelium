import { test } from "node:test";
import assert from "node:assert/strict";
import { errLine, prBody, type FixPlan, type PlannedFix } from "../src/fix.ts";

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
