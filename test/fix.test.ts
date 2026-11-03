import { test } from "node:test";
import assert from "node:assert/strict";
import { prBody, type FixPlan, type PlannedFix } from "../src/fix.ts";

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
