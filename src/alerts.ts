// Email when something urgent lands: any new critical, or enough new highs. One email per check, never one per advisory.
//
// "New" means not yet emailed, tracked in its own table: `notified` belongs to macOS notifications and `mycelium check`,
// which mark things as seen on a screen nobody here may be reading. Turning alerts on records what's already open as a
// baseline, so the first email is about something new rather than the whole backlog.

import type { DatabaseSync } from "node:sqlite";
import { companyName } from "./db.ts";
import { findings, type Finding } from "./graph.ts";
import { fetchRetry } from "./net.ts";

export interface AlertSettings {
  enabled: boolean;
  recipients: string[];
  critical: boolean; // email on any new critical
  highThreshold: number; // email once this many new highs are waiting; 0 turns highs off
}

export interface AlertStatus {
  lastSentAt?: string;
  lastCount?: number;
  lastError?: string;
  lastErrorAt?: string;
}

export interface Email {
  to: string[];
  subject: string;
  html: string;
  text: string;
}
export type Sender = (mail: Email) => Promise<void>;

export const DEFAULT_ALERTS: AlertSettings = { enabled: false, recipients: [], critical: true, highThreshold: 3 };

const getJson = <T>(db: DatabaseSync, key: string, fallback: T): T => {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | undefined;
  return row ? { ...fallback, ...JSON.parse(row.value) } : fallback;
};
const setJson = (db: DatabaseSync, key: string, value: unknown) =>
  db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT DO UPDATE SET value = excluded.value").run(key, JSON.stringify(value));

export const loadAlertSettings = (db: DatabaseSync) => getJson<AlertSettings>(db, "alerts", DEFAULT_ALERTS);
export const loadAlertStatus = (db: DatabaseSync) => getJson<AlertStatus>(db, "alerts_status", {});

const keyOf = (f: Finding) => `${f.ecosystem}|${f.name}@${f.version}|${f.vulnId}`;
const isCritical = (f: Finding) => f.severity === "CRITICAL" || f.vulnId.startsWith("MAL-"); // a malicious package is always urgent

function waiting(db: DatabaseSync): { critical: Finding[]; high: Finding[] } {
  const sent = new Set((db.prepare("SELECT key FROM alerted").all() as { key: string }[]).map((r) => r.key));
  const fresh = findings(db).filter((f) => !sent.has(keyOf(f)));
  return { critical: fresh.filter(isCritical), high: fresh.filter((f) => !isCritical(f) && f.severity === "HIGH") };
}

function markAlerted(db: DatabaseSync, list: Finding[]) {
  const at = new Date().toISOString();
  const ins = db.prepare("INSERT OR IGNORE INTO alerted (key, alerted_at) VALUES (?, ?)");
  for (const f of list) ins.run(keyOf(f), at);
}

/** Saves the settings. Returns how many open findings became the baseline, when this turned alerts on. */
export function saveAlertSettings(db: DatabaseSync, input: Partial<AlertSettings>): { settings: AlertSettings; baselined: number } {
  const prev = loadAlertSettings(db);
  const recipients = [...new Set((input.recipients ?? prev.recipients).map((r) => String(r).trim().toLowerCase()).filter(Boolean))];
  const bad = recipients.find((r) => !/^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/.test(r));
  if (bad) throw new Error(`"${bad}" doesn't look like an email address.`);
  const highThreshold = Number(input.highThreshold ?? prev.highThreshold);
  if (!Number.isInteger(highThreshold) || highThreshold < 0 || highThreshold > 1000) throw new Error("The number of highs has to be a whole number, 0 or more.");
  const settings: AlertSettings = { enabled: !!(input.enabled ?? prev.enabled), recipients, critical: !!(input.critical ?? prev.critical), highThreshold };
  if (settings.enabled && !recipients.length) throw new Error("Add at least one email address to turn alerts on.");
  let baselined = 0;
  if (settings.enabled && !prev.enabled) {
    const { critical, high } = waiting(db);
    markAlerted(db, [...critical, ...high]);
    baselined = critical.length + high.length;
  }
  setJson(db, "alerts", settings);
  return { settings, baselined };
}

/** What a check's results call for under these settings. Highs below the threshold keep waiting and count towards it next time. */
export function pickAlert(s: AlertSettings, w: { critical: Finding[]; high: Finding[] }): Finding[] {
  const critical = s.critical ? w.critical : [];
  const highs = s.highThreshold > 0 ? w.high : [];
  const trigger = critical.length > 0 || (s.highThreshold > 0 && highs.length >= s.highThreshold);
  return trigger ? [...critical, ...highs] : [];
}

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const safeUrl = (u: unknown) => (/^https?:\/\//i.test(String(u ?? "")) ? esc(u) : "");
const projectsOf = (f: Finding) => [...new Set(f.hits.map((h) => h.project))];

export function buildAlertEmail(list: Finding[], recipients: string[], baseUrl: string | null, company = ""): Email {
  const ordered = [...list].sort((a, b) => Number(isCritical(b)) - Number(isCritical(a)) || b.risk - a.risk);
  const crit = list.filter(isCritical).length, high = list.length - crit;
  const projects = [...new Set(list.flatMap(projectsOf))];
  const what = [crit && `${crit} critical`, high && `${high} high`].filter(Boolean).join(", ");
  const where = projects.length === 1 ? projects[0] : `${projects.length} projects`;
  const link = (project: string) => (baseUrl ? `${baseUrl.replace(/\/$/, "")}/#project=${encodeURIComponent(project)}` : "");
  const fix = (f: Finding) => (f.fixed ? `fixed in ${f.fixed}` : "no fix available yet");

  const rows = ordered.map((f) => {
    const id = f.cve ?? f.vulnId;
    const url = safeUrl(f.url);
    const names = projectsOf(f).map((p) => (link(p) ? `<a href="${esc(link(p))}">${esc(p)}</a>` : esc(p))).join(", ");
    return `<tr><td style="padding:8px;border-top:1px solid #e6e4ef;font-weight:700;color:${isCritical(f) ? "#c4221a" : "#cf5116"}">${isCritical(f) ? "CRITICAL" : "HIGH"}</td>
      <td style="padding:8px;border-top:1px solid #e6e4ef"><b>${esc(f.name)}</b> ${esc(f.version)}<br><span style="color:#6b6980">${esc(fix(f))}</span></td>
      <td style="padding:8px;border-top:1px solid #e6e4ef">${url ? `<a href="${url}">${esc(id)}</a>` : esc(id)}<br>${esc(f.summary)}</td>
      <td style="padding:8px;border-top:1px solid #e6e4ef">${names}</td></tr>`;
  }).join("");
  const open = baseUrl ? `<p><a href="${esc(baseUrl)}">Open Mycelium</a> to check these and open fix PRs.</p>` : "";
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px;color:#15131f">
    <p><b>Mycelium found ${esc(what)} new ${list.length === 1 ? "vulnerability" : "vulnerabilities"} in ${esc(where)}.</b></p>
    <table style="border-collapse:collapse;font-size:13px;text-align:left"><tr><th style="padding:8px">Severity</th><th style="padding:8px">Package</th><th style="padding:8px">Advisory</th><th style="padding:8px">Projects</th></tr>${rows}</table>
    ${open}<p style="color:#6b6980;font-size:12px">You get this because your address is on Mycelium's alert list. Change it on the Alerts page.</p></div>`;
  const text = [`Mycelium found ${what} new ${list.length === 1 ? "vulnerability" : "vulnerabilities"} in ${where}.`, "",
    ...ordered.map((f) => `${isCritical(f) ? "CRITICAL" : "HIGH"}  ${f.name} ${f.version} (${fix(f)})  ${f.cve ?? f.vulnId}  in ${projectsOf(f).join(", ")}\n  ${f.summary}`),
    ...(baseUrl ? ["", `Open Mycelium: ${baseUrl}`] : [])].join("\n");
  // Package names and summaries come from outside: no line breaks in a header.
  return { to: recipients, subject: `${company ? `[${company}] ` : ""}Mycelium: ${what} in ${where}`.replace(/[\r\n]+/g, " "), html, text };
}

// ---------------------------------------------------------------- sending

export const emailConfigured = (env = process.env) => !!(env.RESEND_API_KEY && env.MYCELIUM_EMAIL_FROM);
export const emailFrom = (env = process.env) => env.MYCELIUM_EMAIL_FROM ?? null;

export const resendSender: Sender = async (mail) => {
  if (!emailConfigured()) throw new Error("Email isn't set up: RESEND_API_KEY and MYCELIUM_EMAIL_FROM are needed.");
  // Two tries only: a retry after a dropped response could send a duplicate, which beats losing a critical but shouldn't repeat.
  const r = await fetchRetry("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ from: process.env.MYCELIUM_EMAIL_FROM, ...mail }),
  }, { tries: 2, timeoutMs: 30_000 });
  if (!r.ok) throw new Error(emailError(r.status, await r.text()));
};

/** A sentence for the Alerts page, not the service's raw JSON. */
export function emailError(status: number, body: string): string {
  if (status === 401 || status === 403) return "The email service rejected the API key. Check RESEND_API_KEY.";
  let message = body.slice(0, 300);
  try {
    message = String(JSON.parse(body).message ?? message);
  } catch { /* not JSON: use the text as it is */ }
  return `The email service refused it (${status}): ${message}`;
}

/**
 * Run after every check. Sends at most one email, and only marks findings once it went out, so a failed send is retried
 * by the next check. Never throws: losing an email shouldn't fail the rescan that found the problem. The Alerts page shows the error.
 */
export async function runAlerts(db: DatabaseSync, baseUrl: string | null, send: Sender = resendSender): Promise<{ sent: number; error?: string }> {
  const s = loadAlertSettings(db);
  if (!s.enabled || !s.recipients.length) return { sent: 0 };
  const list = pickAlert(s, waiting(db));
  if (!list.length) return { sent: 0 };
  const status = loadAlertStatus(db);
  try {
    await send(buildAlertEmail(list, s.recipients, baseUrl, companyName(db)));
  } catch (e) {
    const error = (e as Error).message;
    setJson(db, "alerts_status", { ...status, lastError: error, lastErrorAt: new Date().toISOString() });
    return { sent: 0, error };
  }
  markAlerted(db, list);
  setJson(db, "alerts_status", { lastSentAt: new Date().toISOString(), lastCount: list.length });
  return { sent: list.length };
}

export async function sendTestEmail(db: DatabaseSync, baseUrl: string | null, recipients: string[], send: Sender = resendSender) {
  if (!recipients.length) throw new Error("Add an email address first.");
  await send({
    to: recipients,
    subject: "Mycelium: test alert",
    text: `This is a test. Mycelium can reach this address.${baseUrl ? `\n\n${baseUrl}` : ""}`,
    html: `<p>This is a test. Mycelium can reach this address.</p>${baseUrl ? `<p><a href="${esc(baseUrl)}">Open Mycelium</a></p>` : ""}`,
  });
}

/** For the Alerts page: what's waiting, and why it hasn't gone out. */
export function alertsView(db: DatabaseSync) {
  const { critical, high } = waiting(db);
  return { settings: loadAlertSettings(db), status: loadAlertStatus(db), configured: emailConfigured(), from: emailFrom(), waiting: { critical: critical.length, high: high.length } };
}
