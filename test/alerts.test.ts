import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAlertEmail, emailError, loadAlertStatus, pickAlert, runAlerts, saveAlertSettings, type Email } from "../src/alerts.ts";
import { openDb } from "../src/db.ts";
import type { Finding } from "../src/graph.ts";

function seed(db: ReturnType<typeof openDb>, name: string, severity: string, vuln = `GHSA-${name}`, scope = "prod") {
  const pr = db.prepare("SELECT id FROM projects WHERE name = 'app'").get() as { id: number } | undefined;
  const projectId = pr?.id ?? Number(db.prepare("INSERT INTO projects (name, path, exposure, scanned_at) VALUES ('app', '/r/app', 'public-web', 'now')").run().lastInsertRowid);
  const comp = Number(db.prepare("INSERT INTO components (project_id, kind, path, ecosystem) VALUES (?, 'npm', ?, 'npm')").run(projectId, `${name}/package-lock.json`).lastInsertRowid);
  const pkg = Number(db.prepare("INSERT INTO packages (ecosystem, name, version) VALUES ('npm', ?, '1.0.0')").run(name).lastInsertRowid);
  db.prepare("INSERT INTO uses (component_id, package_id, direct, scope) VALUES (?, ?, 1, ?)").run(comp, pkg, scope);
  db.prepare("INSERT INTO vulns (id, summary, severity, aliases, modified) VALUES (?, 'bad', ?, '[]', 'now')").run(vuln, severity);
  db.prepare("INSERT INTO package_vulns (package_id, vuln_id, fixed, first_seen) VALUES (?, ?, '1.0.1', 'now')").run(pkg, vuln);
}
const inbox = () => {
  const sent: Email[] = [];
  return { sent, send: async (m: Email) => void sent.push(m) };
};
const on = (db: ReturnType<typeof openDb>) => saveAlertSettings(db, { enabled: true, recipients: ["a@b.co"] });

test("turning alerts on baselines the backlog: the first email is about something new", async () => {
  const db = openDb(":memory:");
  seed(db, "old-crit", "CRITICAL");
  seed(db, "old-high", "HIGH");
  assert.equal(on(db).baselined, 2);
  const box = inbox();
  assert.deepEqual(await runAlerts(db, null, box.send), { sent: 0 });
  seed(db, "new-crit", "CRITICAL");
  assert.equal((await runAlerts(db, null, box.send)).sent, 1);
  assert.equal(box.sent.length, 1);
  assert.match(box.sent[0].text, /new-crit/);
  assert.doesNotMatch(box.sent[0].text, /old-crit/);
  assert.equal((await runAlerts(db, null, box.send)).sent, 0, "never emailed twice");
});

test("highs wait for the threshold, and count across checks", async () => {
  const db = openDb(":memory:");
  on(db);
  const box = inbox();
  seed(db, "h1", "HIGH");
  seed(db, "h2", "HIGH");
  await runAlerts(db, null, box.send);
  assert.equal(box.sent.length, 0);
  seed(db, "h3", "HIGH");
  assert.equal((await runAlerts(db, null, box.send)).sent, 3, "the third high sets it off and all three are listed");
  assert.equal(box.sent.length, 1, "one email, not one per advisory");
});

test("a failed send isn't marked, so the next check retries it, and the error is kept for the page", async () => {
  const db = openDb(":memory:");
  on(db);
  seed(db, "c", "CRITICAL");
  const out = await runAlerts(db, null, async () => { throw new Error("401 bad key"); });
  assert.equal(out.sent, 0);
  assert.match(loadAlertStatus(db).lastError!, /401/);
  const box = inbox();
  assert.equal((await runAlerts(db, null, box.send)).sent, 1);
  assert.equal(loadAlertStatus(db).lastError, undefined, "success clears the error");
});

test("moderates, dev-only and accepted findings never email", async () => {
  const db = openDb(":memory:");
  on(db);
  seed(db, "mod", "MODERATE");
  seed(db, "dev", "CRITICAL", "GHSA-dev", "dev");
  seed(db, "fine", "CRITICAL", "GHSA-fine");
  db.prepare("INSERT INTO settings (key, value) VALUES ('accepted', ?)").run(JSON.stringify([{ name: "fine", vulnIds: ["GHSA-fine"], projects: ["app"], reason: "r", acceptedAt: "2026-01-01", expires: "2099-01-01" }]));
  const box = inbox();
  await runAlerts(db, null, box.send);
  assert.equal(box.sent.length, 0);
});

test("the rule follows the settings; a malicious package is always critical", async () => {
  const f = (severity: string, vulnId = "GHSA-1") => ({ severity, vulnId }) as Finding;
  const base = { enabled: true, recipients: ["a@b.co"], critical: true, highThreshold: 3 };
  assert.equal(pickAlert({ ...base, critical: false }, { critical: [f("CRITICAL")], high: [] }).length, 0);
  assert.equal(pickAlert({ ...base, highThreshold: 0 }, { critical: [], high: [f("HIGH"), f("HIGH"), f("HIGH")] }).length, 0);
  assert.equal(pickAlert({ ...base, highThreshold: 1 }, { critical: [], high: [f("HIGH")] }).length, 1);
  const db = openDb(":memory:");
  on(db);
  seed(db, "evil", "UNKNOWN", "MAL-2026-1");
  const box = inbox();
  await runAlerts(db, null, box.send);
  assert.match(box.sent[0].subject, /1 critical/);
});

test("email service errors read as sentences", () => {
  assert.match(emailError(401, '{"message":"API key is invalid"}'), /rejected the API key/);
  assert.equal(emailError(422, '{"message":"Invalid from address"}'), "The email service refused it (422): Invalid from address");
  assert.equal(emailError(500, "oops"), "The email service refused it (500): oops");
});

test("settings are validated", () => {
  const db = openDb(":memory:");
  assert.throws(() => saveAlertSettings(db, { enabled: true, recipients: [] }), /at least one/);
  assert.throws(() => saveAlertSettings(db, { recipients: ["nope"] }), /doesn't look like/);
  assert.throws(() => saveAlertSettings(db, { recipients: ["a@b.co\nBcc: x@y.z"] }), /doesn't look like/);
  assert.throws(() => saveAlertSettings(db, { highThreshold: -1 }), /whole number/);
});

test("email content is escaped, can't break the subject line, and links to the project", () => {
  const f = { severity: "CRITICAL", vulnId: "GHSA-1", cve: null, summary: "<script>x</script>", name: "<b>evil\r\nBcc: x@y.z", version: "1", fixed: null, url: "javascript:alert(1)", risk: 1, hits: [{ project: "my app" }] } as unknown as Finding;
  const m = buildAlertEmail([f], ["a@b.co"], "https://m.example/");
  assert.doesNotMatch(m.html, /<script>|javascript:|<b>evil/);
  assert.doesNotMatch(m.subject, /[\r\n]/);
  assert.match(m.html, /https:\/\/m\.example\/#project=my%20app/);
  assert.match(m.subject, /^Mycelium: 1 critical in my app/);
  assert.match(buildAlertEmail([f], ["a@b.co"], null, "Acme").subject, /^\[Acme\] Mycelium/);
});
