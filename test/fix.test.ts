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
