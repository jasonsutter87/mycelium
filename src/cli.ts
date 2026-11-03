// mycelium: map every dependency under everything you own, and know when a CVE lands in it.

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { DB_PATH, openDb } from "./db.ts";
import { scanRoots } from "./scan.ts";
import { applyFixes, planFixes, type ApplyResult, type FixPlan } from "./fix.ts";
import { audit, CATEGORY_LABEL } from "./audit.ts";
import { enrich } from "./depsdev.ts";
import { severityRank } from "./osv.ts";
import { checkAll } from "./osv.ts";
import { findings, fixCommand, impact, whyPaths, type Finding } from "./graph.ts";
import { writeHtmlReport } from "./report.ts";

const [cmd = "help", ...rest] = process.argv.slice(2);
const VALUE_FLAGS = new Set(["--top", "--hour", "--project", "--html", "--min", "--only", "--port", "--category"]);
const flags = new Set<string>();
const values = new Map<string, string>();
const args: string[] = [];
for (let i = 0; i < rest.length; i++) {
  const a = rest[i];
  if (!a.startsWith("--")) args.push(a);
  else {
    flags.add(a);
    if (VALUE_FLAGS.has(a) && rest[i + 1] && !rest[i + 1].startsWith("--")) values.set(a, rest[++i]);
  }
}
const flagValue = (name: string) => values.get(name);

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string | number) => (tty ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { dim: paint("2"), bold: paint("1"), red: paint("31"), yellow: paint("33"), green: paint("32"), cyan: paint("36"), magenta: paint("35") };
const SEV_COLOR: Record<string, (s: string) => string> = {
  CRITICAL: (s) => c.bold(c.red(s)), HIGH: c.red, MODERATE: c.yellow, LOW: c.dim, UNKNOWN: c.dim,
};

const db = openDb();
const getSetting = (k: string) => (db.prepare("SELECT value FROM settings WHERE key = ?").get(k) as { value: string } | undefined)?.value;
const setSetting = (k: string, v: string) =>
  db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT DO UPDATE SET value = excluded.value").run(k, v);

// ---------------------------------------------------------------- commands

function scan(roots: string[]) {
  const list = roots.length ? roots.map((r) => resolve(r)) : JSON.parse(getSetting("roots") ?? "null") ?? [process.cwd()];
  setSetting("roots", JSON.stringify(list));
  const scanned = scanRoots(db, list);
  for (const s of scanned) {
    console.log(`${c.green("●")} ${c.bold(s.name.padEnd(28))} ${String(s.packages).padStart(5)} pkgs  ${c.cyan(s.exposure.padEnd(11))} ${c.dim(s.ecosystems.join(", ") || "—")}`);
    if (flags.has("--verbose")) for (const w of s.warnings) console.log(`    ${c.yellow("!")} ${c.dim(w)}`);
  }
  const total = scanned.length;
  const unique = (db.prepare("SELECT count(DISTINCT package_id) n FROM uses").get() as { n: number }).n;
  console.log(c.dim(`\n${total} projects · ${unique} unique packages · db: ${DB_PATH}`));
}

async function check(): Promise<Finding[]> {
  const fresh = await checkAll(db, (s) => console.log(c.dim(s)));
  const freshKeys = new Set(fresh.map((f) => `${f.packageId}|${f.vulnId}`));
  return findings(db, { includeDev: flags.has("--dev") }).filter((f) => freshKeys.has(`${f.packageId}|${f.vulnId}`));
}

function printFinding(f: Finding, detail: boolean) {
  const projects = [...new Set(f.hits.map((h) => h.project))];
  const sev = (SEV_COLOR[f.severity] ?? c.dim)(f.severity.padEnd(8));
  console.log(`${sev} ${c.bold(`${f.name}@${f.version}`)} ${c.dim(f.ecosystem)}  risk ${c.magenta(f.risk)}  ${c.dim(f.cve ?? f.vulnId)}`);
  console.log(`         ${f.summary}`);
  console.log(`         ${c.dim("in:")} ${projects.join(", ")}`);
  if (!detail) return;
  // One block per project: prefer a direct hit, show the shortest path, count the lockfiles.
  const byProject = new Map<string, typeof f.hits>();
  for (const h of f.hits) byProject.set(h.project, [...(byProject.get(h.project) ?? []), h]);
  for (const [project, hs] of byProject) {
    const h = hs.find((x) => x.direct) ?? hs[0];
    const chain = h.direct ? [] : whyPaths(db, h.componentId, f.packageId, 1)[0] ?? [];
    const where = hs.length > 1 ? `${h.component} +${hs.length - 1} more` : h.component;
    console.log(`         ${c.cyan(project)} ${c.dim(`(${h.exposure}, ${where})`)}`);
    if (chain.length > 1) console.log(`           ${c.dim("path:")} ${chain.join(c.dim(" → "))}`);
    console.log(`           ${c.dim("fix: ")} ${fixCommand(f, h.direct, chain[0])}`);
  }
  console.log(`         ${c.dim(f.url)}`);
}

function report() {
  const list = findings(db, { includeDev: flags.has("--dev") });
  if (flags.has("--html")) {
    const out = resolve(flagValue("--html") ?? "report.html");
    writeHtmlReport(db, list, out);
    console.log(`Wrote ${out}`);
    return;
  }
  if (!list.length) {
    console.log(c.green("No known vulnerabilities in production dependencies. 🍄") + c.dim("  (run `mycelium check` to refresh)"));
    return;
  }
  const limit = flags.has("--all") ? Infinity : Number(flagValue("--top") ?? 15);
  for (const f of list.slice(0, limit)) {
    printFinding(f, true);
    console.log();
  }
  summary(list);
  if (list.length > limit) console.log(c.dim(`…${list.length - limit} more. Use --all, or --html for the full report.`));
}

function summary(list: Finding[]) {
  const by = (s: string) => list.filter((f) => f.severity === s).length;
  const projects = new Set(list.flatMap((f) => f.hits.map((h) => h.project)));
  console.log(
    `${c.bold(String(list.length))} findings across ${c.bold(String(projects.size))} projects: ` +
      `${SEV_COLOR.CRITICAL(`${by("CRITICAL")} critical`)}, ${SEV_COLOR.HIGH(`${by("HIGH")} high`)}, ` +
      `${SEV_COLOR.MODERATE(`${by("MODERATE")} moderate`)}, ${c.dim(`${by("LOW") + by("UNKNOWN")} low/unknown`)}`,
  );
}

function why(target: string) {
  const [name, version] = splitTarget(target);
  const rows = impact(db, name, version).filter((r) => !flagValue("--project") || r.project === flagValue("--project"));
  if (!rows.length) return console.log(`Nothing in the graph uses ${target}.`);
  for (const r of rows) {
    console.log(`${c.cyan(r.project)} ${c.dim(r.component)} ${r.name}@${r.version} ${c.dim(r.direct ? "direct" : "transitive")} ${c.dim(r.scope)}`);
    if (!r.direct) for (const p of whyPaths(db, r.component_id, r.package_id, 3)) console.log(`   ${p.join(c.dim(" → "))}`);
  }
}

function impactCmd(target: string) {
  const [name, version] = splitTarget(target);
  const rows = impact(db, name, version);
  if (!rows.length) return console.log(c.green(`No project uses ${target}.`));
  const byProject = new Map<string, any[]>();
  for (const r of rows) byProject.set(r.project, [...(byProject.get(r.project) ?? []), r]);
  console.log(`${c.bold(target)} is in ${c.bold(String(byProject.size))} projects:\n`);
  for (const [project, rs] of byProject) {
    const versions = [...new Set(rs.map((r) => r.version))].join(", ");
    const direct = rs.some((r) => r.direct) ? "direct" : "transitive";
    console.log(`  ${c.cyan(project.padEnd(28))} ${versions.padEnd(18)} ${c.dim(direct.padEnd(10))} ${c.dim(rs[0].exposure)}`);
  }
}

function projects() {
  const rows = db.prepare(`
    SELECT pr.id, pr.name, pr.exposure,
      (SELECT count(DISTINCT u.package_id) FROM uses u JOIN components c ON c.id = u.component_id WHERE c.project_id = pr.id) AS pkgs,
      (SELECT count(DISTINCT pv.vuln_id) FROM package_vulns pv JOIN uses u ON u.package_id = pv.package_id
         JOIN components c ON c.id = u.component_id WHERE c.project_id = pr.id AND u.scope = 'prod') AS vulns
    FROM projects pr ORDER BY vulns DESC, pr.name`).all() as any[];
  const infraStmt = db.prepare("SELECT DISTINCT kind, value FROM infra WHERE project_id = ? AND kind IN ('host','domain','distribution')");
  for (const r of rows) {
    const where = (infraStmt.all(r.id) as any[]).map((i) => i.value).join(", ");
    const v = r.vulns ? c.red(`${r.vulns} vulns`.padEnd(9)) : c.green("clean".padEnd(9));
    console.log(`${c.bold(r.name.padEnd(28))} ${String(r.pkgs).padStart(5)} pkgs  ${v} ${c.cyan(r.exposure.padEnd(11))} ${c.dim(where)}`);
  }
}

function infra() {
  const rows = db.prepare(`
    SELECT pr.name AS project, i.kind, i.value, i.source, i.warning FROM infra i JOIN projects pr ON pr.id = i.project_id
    ORDER BY i.warning IS NULL, pr.name, i.kind`).all() as any[];
  const onlyWarn = !flags.has("--all");
  let n = 0;
  for (const r of rows) {
    if (onlyWarn && !r.warning) continue;
    n++;
    console.log(`${c.cyan(r.project.padEnd(24))} ${r.kind.padEnd(13)} ${r.value} ${r.warning ? c.yellow("⚠ " + r.warning) : ""} ${c.dim(r.source)}`);
  }
  if (onlyWarn) console.log(c.dim(`\n${n} infrastructure warnings. --all lists every host/domain/image/action.`));
}

async function watch() {
  scan(args);
  const fresh = await check();
  if (!fresh.length) {
    console.log(c.dim(`${new Date().toISOString()} no new vulnerabilities.`));
    return;
  }
  console.log(c.bold(`\n${fresh.length} NEW finding(s):\n`));
  for (const f of fresh) {
    printFinding(f, true);
    console.log();
  }
  const worst = fresh[0];
  const projects = new Set(fresh.flatMap((f) => f.hits.map((h) => h.project)));
  const malicious = fresh.filter((f) => f.vulnId.startsWith("MAL-"));
  if (malicious.length) {
    notify(`🚨 MALICIOUS package in ${[...new Set(malicious.flatMap((f) => f.hits.map((h) => h.project)))].join(", ")}`,
      `${malicious.map((f) => `${f.name}@${f.version}`).join(", ")}. Remove it and rotate secrets on machines that installed it.`);
  }
  notify(
    `${fresh.length} new vuln${fresh.length > 1 ? "s" : ""} in ${projects.size} project${projects.size > 1 ? "s" : ""}`,
    `${worst.severity}: ${worst.name}@${worst.version} → ${[...new Set(worst.hits.map((h) => h.project))].join(", ")}`,
  );
  const mark = db.prepare("UPDATE package_vulns SET notified = 1 WHERE package_id = ? AND vuln_id = ?");
  for (const f of fresh) mark.run(f.packageId, f.vulnId);
}

function notify(title: string, body: string) {
  if (process.platform !== "darwin") return;
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  try {
    execFileSync("osascript", ["-e", `display notification "${esc(body)}" with title "🍄 Mycelium" subtitle "${esc(title)}"`]);
  } catch {}
}

function schedule() {
  const hour = Number(flagValue("--hour") ?? 9);
  const roots = args.length ? args.map((r) => resolve(r)) : JSON.parse(getSetting("roots") ?? "[]");
  if (!roots.length) return console.log("Run `mycelium scan <folders>` first, or pass folders to watch.");
  const label = "dev.mycelium.watch";
  const plist = join(homedir(), "Library", "LaunchAgents", `${label}.plist`);
  const logDir = join(homedir(), ".mycelium");
  mkdirSync(logDir, { recursive: true });
  const bin = resolve(import.meta.dirname, "..", "bin", "mycelium");
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>
    <string>${bin}</string><string>watch</string>${roots.map((r: string) => `<string>${r}</string>`).join("")}
  </array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>${process.env.PATH}</string><key>NO_COLOR</key><string>1</string></dict>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>${hour}</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string>${join(logDir, "watch.log")}</string>
  <key>StandardErrorPath</key><string>${join(logDir, "watch.log")}</string>
</dict></plist>`;
  writeFileSync(plist, xml);
  try {
    execFileSync("launchctl", ["unload", plist], { stdio: "ignore" });
  } catch {}
  execFileSync("launchctl", ["load", plist]);
  console.log(`Scheduled daily at ${hour}:00 → ${plist}\nLog: ${join(logDir, "watch.log")}\nRemove: launchctl unload ${plist} && rm ${plist}`);
}

export function printPlan(plan: FixPlan) {
  if (!plan.fixes.length) return console.log(c.green(`${plan.project}: nothing to fix. 🍄`));
  console.log(c.bold(`Fix plan for ${plan.project}`) + c.dim(`  (${plan.projectPath})\n`));
  for (const fx of plan.fixes) {
    const sev = (SEV_COLOR[fx.severity] ?? c.dim)(fx.severity.padEnd(8));
    const tag = fx.strategy === "manual" ? c.yellow("manual ") : fx.breaking ? c.magenta("MAJOR  ") : c.green("auto   ");
    console.log(`${tag} ${sev} ${c.bold(fx.name)} ${fx.from} → ${fx.to ?? "?"}  ${c.dim(`${fx.component} · ${fx.vulns.length} advisories`)}`);
    console.log(`         ${c.dim(fx.note)}`);
  }
  const auto = plan.fixes.filter((f) => f.strategy !== "manual" && !f.breaking).length;
  const major = plan.fixes.filter((f) => f.strategy !== "manual" && f.breaking).length;
  console.log(`\n${c.green(`${auto} automatic`)} · ${c.magenta(`${major} major (need --major)`)} · ${c.yellow(`${plan.fixes.length - auto - major} manual`)}`);
}

export function printApply(r: ApplyResult) {
  for (const l of r.log) console.log(c.dim(l));
  if (r.fixed.length) console.log(c.green(`\n✓ fixed ${r.fixed.length}:`) + "\n  " + r.fixed.join("\n  "));
  if (r.stillVulnerable.length) console.log(c.yellow(`\n! still vulnerable after apply ${r.stillVulnerable.length}:`) + "\n  " + r.stillVulnerable.join("\n  "));
  if (r.failed.length) console.log(c.red(`\n✗ failed ${r.failed.length}:`) + "\n  " + r.failed.map((f) => `${f.fix.name}: ${f.error.split("\n")[0]}`).join("\n  "));
  if (r.skipped.length) console.log(c.dim(`\nskipped ${r.skipped.length}: `) + c.dim(r.skipped.map((s) => s.fix.name).join(", ")));
  for (const v of r.verify) {
    if (v.ok) console.log(`${c.green("✓")} ${v.command} ${c.dim(v.dir)}`);
    else if (v.preexisting) console.log(`${c.yellow("≈")} ${v.command} ${c.dim(v.dir)} ${c.yellow("fails the same way before the upgrade: pre-existing, not blocking")}`);
    else console.log(`${c.red("✗")} ${v.command} ${c.dim(v.dir)}\n${c.dim(v.output.slice(-800))}`);
  }
  for (const p of r.prs) console.log(`\n${c.green("⇪ PR opened")} → ${c.bold(p.url)} ${c.dim(`(into ${p.base})`)}`);
  if (r.branch) {
    console.log(`\nCommitted on branch ${c.cyan(r.branch)}. Your working folder wasn't touched.`);
    console.log(c.dim(`Review: git log -p ${r.branch} -1   ·   Use it: git merge ${r.branch}   ·   Drop it: git branch -D ${r.branch}`));
  }
}

async function fix(project: string) {
  const plan = planFixes(db, project, { minSeverity: flagValue("--min")?.toUpperCase(), includeDev: flags.has("--dev") });
  if (!flags.has("--apply")) {
    printPlan(plan);
    if (plan.fixes.some((f) => f.strategy !== "manual")) console.log(c.dim(`\nApply with: mycelium fix ${project} --apply [--verify] [--pr] [--major]`));
    return;
  }
  const r = applyFixes(db, plan, {
    allowMajor: flags.has("--major"), verify: flags.has("--verify"),
    only: flagValue("--only")?.split(","), dryRun: flags.has("--dry-run"), pr: flags.has("--pr"),
  });
  printApply(r);
  if (r.applied.length && !flags.has("--dry-run")) {
    await checkAll(db);
    console.log(c.dim("\nRe-checked OSV. `mycelium projects` shows the new counts."));
  }
}

async function auditCmd() {
  if (!flags.has("--offline")) await enrich(db, (s) => console.log(c.dim(s)));
  const project = flagValue("--project");
  const category = flagValue("--category");
  const list = audit(db, { project, category });
  const minRank = severityRank((flagValue("--min") ?? "LOW").toUpperCase());
  const shown = list.filter((i) => severityRank(i.severity) >= minRank);
  const limit = flags.has("--all") ? Infinity : Number(flagValue("--top") ?? 8);

  for (const cat of Object.keys(CATEGORY_LABEL) as (keyof typeof CATEGORY_LABEL)[]) {
    const items = shown.filter((i) => i.category === cat);
    const total = list.filter((i) => i.category === cat).length;
    console.log(`\n${c.bold(CATEGORY_LABEL[cat])} ${c.dim(`(${total})`)}`);
    if (!items.length) {
      console.log(`  ${c.green("✓ nothing found")}`);
      continue;
    }
    for (const i of items.slice(0, limit)) {
      const sev = (SEV_COLOR[i.severity] ?? c.dim)(i.severity.padEnd(8));
      console.log(`  ${sev} ${c.cyan(i.project)} ${i.title}${i.source ? c.dim("  " + i.source) : ""}`);
      if (i.detail) console.log(`           ${c.dim(i.detail.length > 220 ? i.detail.slice(0, 220) + "…" : i.detail)}`);
    }
    if (items.length > limit) console.log(c.dim(`  …${items.length - limit} more (--all, or --category ${cat})`));
  }
  const by = (s: string) => shown.filter((i) => i.severity === s).length;
  console.log(`\n${shown.length} issues: ${SEV_COLOR.CRITICAL(`${by("CRITICAL")} critical`)}, ${SEV_COLOR.HIGH(`${by("HIGH")} high`)}, ${SEV_COLOR.MODERATE(`${by("MODERATE")} moderate`)}, ${c.dim(`${by("LOW")} low`)}` +
    c.dim("   (CVEs are separate: `mycelium report`)"));
}

/** Keeps `mycelium serve` running in the background (starts at login, restarts if it dies). */
function installServe(port: number) {
  const label = "dev.mycelium.serve";
  const plist = join(homedir(), "Library", "LaunchAgents", `${label}.plist`);
  const logDir = join(homedir(), ".mycelium");
  mkdirSync(logDir, { recursive: true });
  const bin = resolve(import.meta.dirname, "..", "bin", "mycelium");
  const env: Record<string, string> = { PATH: process.env.PATH ?? "", MYCELIUM_NO_OPEN: "1", MYCELIUM_DB: DB_PATH, HOME: homedir() };
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array><string>${bin}</string><string>serve</string><string>--port</string><string>${port}</string></array>
  <key>EnvironmentVariables</key><dict>${Object.entries(env).map(([k, v]) => `<key>${k}</key><string>${v}</string>`).join("")}</dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${join(logDir, "serve.log")}</string>
  <key>StandardErrorPath</key><string>${join(logDir, "serve.log")}</string>
</dict></plist>`;
  writeFileSync(plist, xml);
  try {
    execFileSync("launchctl", ["unload", plist], { stdio: "ignore" });
  } catch {}
  execFileSync("launchctl", ["load", plist]);
  console.log(`🍄 Mycelium is always on at ${c.bold(`http://mycelium.localhost:${port}`)}  (bookmark it)`);
  console.log(c.dim(`Starts at login, restarts if it stops. Log: ${join(logDir, "serve.log")}\nTurn off: mycelium serve --uninstall`));
}

function uninstallAgent(label: string) {
  const plist = join(homedir(), "Library", "LaunchAgents", `${label}.plist`);
  try {
    execFileSync("launchctl", ["unload", plist], { stdio: "ignore" });
  } catch {}
  try {
    rmSync(plist);
    console.log(`Removed ${label}.`);
  } catch {
    console.log(`${label} wasn't installed.`);
  }
}

function splitTarget(t: string): [string, string | undefined] {
  const at = t.lastIndexOf("@");
  return at > 0 ? [t.slice(0, at), t.slice(at + 1)] : [t, undefined];
}

const HELP = `${c.bold("mycelium")}: map every dependency under everything you own; know when a CVE lands in it.

  ${c.cyan("scan")} [folders…]      Map projects (a folder of projects, or one project). Remembers the folders.
  ${c.cyan("check")}                Query OSV.dev for every package in the graph; print what's new.
  ${c.cyan("report")}               Ranked findings with paths + fix commands.  --top N | --all | --dev | --html [file]
  ${c.cyan("projects")}             Every project: package count, open vulns, exposure, where it lives.
  ${c.cyan("impact")} <pkg[@ver]>   "A CVE just dropped for X. Which of my projects use it?"
  ${c.cyan("why")} <pkg[@ver]>      How a package got into each project (dependency chains).
  ${c.cyan("audit")}                Everything that isn't a CVE: malicious packages, untrusted sources / dependency
                       confusion, licenses, deprecated, outdated, abandoned, container + CI config, committed
                       secrets.  --category X | --project X | --min high | --all | --offline
  ${c.cyan("infra")}                Map of hosts / domains / images / actions.  --all for everything
  ${c.cyan("fix")} <project>        Plan fixes (dry). --apply commits them to a new branch via a separate worktree
                       (your folder is never touched); --verify runs build/test, --pr pushes + opens a
                       GitHub PR, --major allows major bumps, --min high, --only pkg1,pkg2
  ${c.cyan("prs")}                  Mycelium's PRs: open / merged, and whether a safe pull is possible.
  ${c.cyan("pull")} <project>       Fast-forward a merged fix into your folder (only when safe), then rescan.
  ${c.cyan("serve")} [--port 4747] Local report with Fix buttons at http://mycelium.localhost:4747
                       --install keeps it always on (login item) · --uninstall turns that off
  ${c.cyan("mcp")}                  Run as an MCP server (stdio) so Claude Code can scan, plan and fix.
  ${c.cyan("watch")} [folders…]     scan + check + macOS notification for new findings (for cron/launchd).
  ${c.cyan("schedule")} [--hour 9]  Install a daily launchd job that runs watch.

  Dev-only dependencies are hidden from findings unless you pass --dev.
  DB: ${DB_PATH}`;

try {
switch (cmd) {
  case "scan": scan(args); break;
  case "check": {
    const fresh = await check();
    console.log(fresh.length ? c.bold(`\n${fresh.length} new finding(s):\n`) : c.green("\nNothing new."));
    for (const f of fresh.slice(0, 10)) { printFinding(f, false); console.log(); }
    if (fresh.length > 10) console.log(c.dim(`…and ${fresh.length - 10} more. \`mycelium report\` ranks them all.\n`));
    summary(findings(db, { includeDev: flags.has("--dev") }));
    // `check` is interactive: what you've seen counts as notified.
    const mark = db.prepare("UPDATE package_vulns SET notified = 1 WHERE package_id = ? AND vuln_id = ?");
    for (const f of fresh) mark.run(f.packageId, f.vulnId);
    break;
  }
  case "report": report(); break;
  case "projects": projects(); break;
  case "impact": args[0] ? impactCmd(args[0]) : console.log("usage: mycelium impact <package[@version]>"); break;
  case "why": args[0] ? why(args[0]) : console.log("usage: mycelium why <package[@version]> [--project name]"); break;
  case "infra": infra(); break;
  case "watch": await watch(); break;
  case "audit": await auditCmd(); break;
  case "prs": {
    const { syncPrs, projectPrs } = await import("./prs.ts");
    await syncPrs(db, (s) => console.log(c.dim(s)));
    for (const p of db.prepare("SELECT name, path FROM projects ORDER BY name").all() as { name: string; path: string }[]) {
      for (const s of projectPrs(db, p.path)) {
        const state = s.needsPull ? (s.ready ? c.green("merged · ready to pull") : c.yellow(`merged · can't pull: ${s.reason}`)) : c.cyan("open");
        console.log(`${c.bold(p.name.padEnd(24))} #${String(s.pr.number).padEnd(4)} ${state}  ${c.dim(s.pr.url)}`);
      }
    }
    break;
  }
  case "pull": {
    const { pullProject, syncPrs } = await import("./prs.ts");
    const row = db.prepare("SELECT path FROM projects WHERE name = ?").get(args[0] ?? "") as { path: string } | undefined;
    if (!row) { console.log("usage: mycelium pull <project>"); break; }
    const r = pullProject(db, row.path);
    for (const p of r.pulled) console.log(c.green(`⬇ pulled ${p}`));
    for (const x of r.refused) console.log(c.yellow(`✗ ${x}`));
    if (r.pulled.length) { await checkAll(db); await syncPrs(db); console.log(c.dim("rescanned + re-checked")); }
    break;
  }
  case "fix": args[0] ? await fix(args[0]) : console.log("usage: mycelium fix <project> [--apply] [--verify] [--pr] [--major] [--min high] [--only a,b]"); break;
  case "mcp": await import("./mcp.ts"); break;
  case "serve":
    if (flags.has("--install")) installServe(Number(flagValue("--port") ?? 4747));
    else if (flags.has("--uninstall")) uninstallAgent("dev.mycelium.serve");
    else (await import("./serve.ts")).serve(db, Number(flagValue("--port") ?? 4747));
    break;
  case "schedule": schedule(); break;
  default: console.log(HELP);
}
} catch (e) {
  console.error(c.red("✗ ") + (e as Error).message);
  process.exitCode = 1;
}
