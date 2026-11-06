import { test } from "node:test";
import assert from "node:assert/strict";
import { fixedView } from "../src/dashboard.ts";
import { openDb } from "../src/db.ts";
import { prBody, type FixPlan, type PlannedFix } from "../src/fix.ts";
import { parseFixedTable, recordPrHistory } from "../src/prs.ts";

const fx = (over: Partial<PlannedFix>): PlannedFix => ({
  project: "app", projectPath: "/r/app", component: "package-lock.json", ecosystem: "npm", name: "next", from: "16.1.1",
  to: "16.4.1", direct: true, severity: "CRITICAL", vulns: ["GHSA-2464-fhr4-w9xw"], breaking: false, strategy: "bump-direct", note: "", ...over,
});
const plan: FixPlan = { project: "app", projectPath: "/r/app", fixes: [] };
const body = (applied: PlannedFix[], stillVulnerable: string[] = []) => prBody(plan, { applied, stillVulnerable, skipped: [], failed: [], verify: [] });
const pr = (over: object) => ({ url: "https://github.com/o/app/pull/1", number: 1, state: "MERGED", title: "t", createdAt: "2026-11-01T00:00:00Z", mergedAt: "2026-11-02T00:00:00Z", body: "", ...over });

test("parses the table prBody writes: a format change there has to break this", () => {
  const out = parseFixedTable(body([
    fx({ name: "@scope/pkg", breaking: true, vulns: ["GHSA-a", "CVE-1", "RUSTSEC-2", "GHSA-b", "GHSA-c", "GHSA-d"] }),
    fx({ name: "tmp", from: "0.2.5", to: "0.2.6", severity: "HIGH", component: "web/package-lock.json", vulns: ["GHSA-x"] }),
    fx({ name: "kept", from: "1.0.0", to: "1.0.1" }),
  ], ["kept@1.0.0 (package-lock.json)"]));
  assert.equal(out.length, 2, "what the package manager kept isn't listed as fixed");
  assert.deepEqual(out[0], {
    severity: "CRITICAL", name: "@scope/pkg", from: "16.1.1", to: "16.4.1", major: true, lockfile: "package-lock.json",
    advisories: [
      { id: "GHSA-a", url: "https://github.com/advisories/GHSA-a" },
      { id: "CVE-1", url: "https://nvd.nist.gov/vuln/detail/CVE-1" },
      { id: "RUSTSEC-2", url: "https://osv.dev/vulnerability/RUSTSEC-2" },
      { id: "GHSA-b", url: "https://github.com/advisories/GHSA-b" },
    ],
    moreAdvisories: 2,
  });
  assert.equal(out[1].major, false);
  assert.equal(out[1].lockfile, "web/package-lock.json");
});

test("a description with no Fixed table parses to nothing", () => {
  assert.deepEqual(parseFixedTable("Some hand-written PR\n\n| a | b |"), []);
  assert.deepEqual(parseFixedTable(""), []);
  assert.deepEqual(parseFixedTable(null as unknown as string), []);
});

test("parses the hand-written shapes real PRs use", () => {
  // No Severity column, "Advisory" not "Advisories", text after the link (tallybook#39).
  const noSeverity = parseFixedTable("### Fixed\n\n| Package | Upgrade | Lockfile | Advisory |\n|---|---|---|---|\n| `rustls-webpki` | 0.103.15 → 0.103.16 | `Cargo.lock` | [RUSTSEC-1](https://osv.dev/vulnerability/RUSTSEC-1): may accept bad certs |");
  assert.deepEqual(noSeverity, [{ severity: "UNKNOWN", name: "rustls-webpki", from: "0.103.15", to: "0.103.16", major: false, lockfile: "Cargo.lock", advisories: [{ id: "RUSTSEC-1", url: "https://osv.dev/vulnerability/RUSTSEC-1" }], moreAdvisories: 0 }]);
  // A package that left the tree (CryptoBlocks#4).
  const removed = parseFixedTable("### Fixed\n\n| Severity | Package | Upgrade | Lockfile | Advisories |\n|---|---|---|---|---|\n| LOW | `rand` | 0.8.5 → removed (no longer in the tree after the tauri upgrade) | `Cargo.lock` | [R](https://x.y/R) |");
  assert.equal(removed[0].to, null);
  assert.equal(removed[0].major, false);
  // A bullet list (veilforms#9), which stops at the next heading.
  const bullets = parseFixedTable("### Upgraded\n- dompurify@3.3.1 → 3.4.17 (a/package-lock.json)\n- @x/y@1.0.0 → 1.0.1\n\n### Verification\n- z@1 → 2");
  assert.deepEqual(bullets.map((b) => [b.name, b.from, b.to, b.lockfile]), [["dompurify", "3.3.1", "3.4.17", "a/package-lock.json"], ["@x/y", "1.0.0", "1.0.1", ""]]);
  // Prose isn't guessed at (tallybook#43).
  assert.deepEqual(parseFixedTable("`cargo update -p x` (2.14.0 → 2.14.1), which moves **zip 4.6.1 → 9.3.0**."), []);
});

test("history: the project is one that's scanned, even if the description used an older name", () => {
  const db = openDb(":memory:");
  const named = (name: string) => `Security upgrades for **${name}** by Mycelium.`;
  recordPrHistory(db, pr({ body: named("veilforms") }), ["VeilSuite"]);
  recordPrHistory(db, pr({ url: "https://github.com/o/app/pull/2", number: 2, body: named("Inner") }), ["Outer", "Inner"]);
  recordPrHistory(db, pr({ url: "https://github.com/o/app/pull/3", number: 3, body: named("Gone") }), []);
  const byNumber = new Map((fixedView(db) as any[]).map((r) => [r.number, r.project]));
  assert.equal(byNumber.get(1), "VeilSuite");
  assert.equal(byNumber.get(2), "Inner");
  assert.equal(byNumber.get(3), "Gone");
});

test("history: one row per upgrade, newest first, merged and open but never closed", () => {
  const db = openDb(":memory:");
  const two = body([fx({ component: "a/package-lock.json" }), fx({ component: "b/package-lock.json" })]);
  recordPrHistory(db, pr({ body: two }), ["fallback"]);
  recordPrHistory(db, pr({ url: "https://github.com/o/app/pull/2", number: 2, state: "OPEN", mergedAt: null, createdAt: "2026-11-03T00:00:00Z", body: "hand-written", title: "by hand" }), ["fallback"]);
  recordPrHistory(db, pr({ url: "https://github.com/o/app/pull/3", number: 3, state: "CLOSED", mergedAt: null, body: two }), ["fallback"]);

  const rows = fixedView(db) as any[];
  assert.deepEqual(rows.map((r) => r.number), [2, 1]);
  assert.equal(rows[0].name, null, "a PR without a table still shows up");
  assert.equal(rows[0].project, "fallback");
  assert.equal(rows[1].project, "fallback");
  assert.equal(rows[1].repo, "o/app");
  assert.deepEqual(rows[1].lockfiles, ["a/package-lock.json", "b/package-lock.json"], "one upgrade in two lockfiles is one row");
});

test("history: worktrees syncing one PR give one record, and later state wins", () => {
  const db = openDb(":memory:");
  recordPrHistory(db, pr({ state: "OPEN", mergedAt: null, body: body([fx({})]) }), ["app"]);
  recordPrHistory(db, pr({ body: body([fx({})]) }), ["app"]);
  const rows = fixedView(db) as any[];
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, "MERGED");
});
