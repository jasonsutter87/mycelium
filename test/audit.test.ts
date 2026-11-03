import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyLicense, majorGap } from "../src/audit.ts";
import {
  checkCompose, checkDockerfile, checkPackageLock, checkRequirements, checkWorkflow, npmrcScopes, projectLicense,
} from "../src/parsers/checks.ts";
import { severityOf } from "../src/osv.ts";

test("license classification: OR picks friendliest, AND strictest", () => {
  assert.equal(classifyLicense("MIT"), "permissive");
  assert.equal(classifyLicense("(MIT OR GPL-3.0-only)"), "permissive");
  assert.equal(classifyLicense("MIT AND GPL-3.0-only"), "copyleft");
  assert.equal(classifyLicense("AGPL-3.0-or-later"), "network-copyleft");
  assert.equal(classifyLicense("LGPL-2.1"), "weak-copyleft");
  assert.equal(classifyLicense("BUSL-1.1"), "non-commercial");
  assert.equal(classifyLicense("Apache-2.0 WITH LLVM-exception"), "permissive");
  assert.equal(classifyLicense("non-standard"), "unknown");
  assert.equal(classifyLicense(undefined), "unknown");
});

test("project license detection", () => {
  assert.equal(projectLicense({ packageJson: '{"license":"MIT"}' }), "MIT");
  assert.equal(projectLicense({ packageJson: '{"license":"UNLICENSED"}' }), "proprietary");
  assert.equal(projectLicense({ cargoToml: '[package]\nlicense = "MIT OR Apache-2.0"' }), "MIT OR Apache-2.0");
  assert.equal(projectLicense({ licenseText: "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3" }), "AGPL-3.0");
});

test("major gap", () => {
  assert.equal(majorGap("16.1.1", "19.0.0"), 3);
  assert.equal(majorGap("0.2.5", "0.4.0"), 2);
  assert.equal(majorGap("0.9.0", "2.1.0"), 2);
  assert.equal(majorGap("5.0.0", "4.0.0"), 0);
});

test("malicious advisories are always CRITICAL", () => {
  assert.equal(severityOf({ id: "MAL-2025-1234" }), "CRITICAL");
});

test("dependency confusion: scoped registry resolved from public npm", () => {
  const scopes = npmrcScopes("@acme:registry=https://npm.acme.internal/\n");
  const lock = JSON.stringify({ packages: {
    "": {},
    "node_modules/@acme/auth": { version: "1.0.0", resolved: "https://registry.npmjs.org/@acme/auth/-/auth-1.0.0.tgz", integrity: "x" },
    "node_modules/left-pad": { version: "1.0.0", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz", integrity: "x" },
    "node_modules/evil": { version: "1.0.0", resolved: "http://mirror.example.net/evil.tgz", integrity: "x" },
    "node_modules/forked": { version: "1.0.0", resolved: "git+ssh://git@github.com/me/forked.git#abc" },
  } });
  const issues = checkPackageLock(lock, "package-lock.json", scopes);
  const titles = issues.map((i) => `${i.severity} ${i.title}`).join("\n");
  assert.match(titles, /HIGH dependency confusion: @acme is mapped to npm\.acme\.internal/);
  assert.match(titles, /HIGH downloaded over plain HTTP/);
  assert.match(titles, /MODERATE installed from git/);
  assert.doesNotMatch(titles, /left-pad/);
});

test("pip --extra-index-url is flagged", () => {
  const i = checkRequirements("--extra-index-url https://user:pw@pypi.acme.dev/simple\nrequests==2.0\n", "requirements.txt");
  assert.equal(i[0].severity, "HIGH");
  assert.doesNotMatch(i[0].detail!, /pw@/); // credentials masked
});

test("container checks", () => {
  const d = checkDockerfile("FROM node:20\nENV API_KEY=sk_live_abcdef123\nRUN curl -fsSL https://x.sh | bash\n", "Dockerfile");
  assert.deepEqual(d.map((i) => i.severity).sort(), ["HIGH", "MODERATE", "MODERATE"]);
  assert.equal(checkDockerfile("FROM node:20\nUSER node\n", "Dockerfile").length, 0);

  const c = checkCompose(`
services:
  db:
    image: postgres:16
    ports: ["5432:5432"]
    environment:
      POSTGRES_PASSWORD: hunter2
  cache:
    image: redis
    ports: ["127.0.0.1:6379:6379"]
  agent:
    image: x
    privileged: true
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
`, "docker-compose.prod.yml");
  const t = c.map((i) => `${i.severity} ${i.title}`);
  assert.ok(t.includes("HIGH db: Postgres port 5432 published on all interfaces"));
  assert.ok(!t.some((x) => x.includes("cache")), "127.0.0.1-bound redis is fine");
  assert.ok(t.some((x) => x.startsWith("MODERATE db: hardcoded secrets")));
  assert.equal(t.filter((x) => x.startsWith("HIGH agent")).length, 2);
});

test("GitHub Actions: pwn request + script injection", () => {
  const w = checkWorkflow(`
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: "\${{ github.event.pull_request.head.sha }}" }
      - run: echo "\${{ github.event.issue.title }}"
`, "ci.yml");
  assert.deepEqual(w.map((i) => i.severity), ["CRITICAL", "HIGH"]);
});
