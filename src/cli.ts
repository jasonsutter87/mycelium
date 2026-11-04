// mycelium: map every dependency under everything you own, and know when a CVE lands in it.

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { DB_PATH, openDb } from "./db.ts";
import { mergeRoots, scanRoots } from "./scan.ts";
import { applyFixes, errLine, planFixes, type ApplyResult, type FixPlan } from "./fix.ts";
import { audit, CATEGORY_LABEL } from "./audit.ts";
import { enrich } from "./depsdev.ts";
import { severityRank } from "./osv.ts";
import { checkAll } from "./osv.ts";
import { acceptanceCovers, acceptedCount, findings, fixCommand, impact, loadAcceptances, whyPaths, type Acceptance, type Finding } from "./graph.ts";
import { writeHtmlReport } from "./report.ts";

const [cmd = "help", ...rest] = process.argv.slice(2);
const VALUE_FLAGS = new Set(["--top", "--hour", "--project", "--html", "--min", "--only", "--port", "--category", "--reason", "--days", "--list"]);
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

/** Headless: keep clones of your repos in <dir>, then scan and check them. */
async function sync(dir?: string) {
  const list = flagValue("--list");
  if (!dir || !list) return fail("Usage: mycelium sync <dir> --list <file with one owner/name per line>");
  const { readRepoList, syncRepos } = await import("./sync.ts");
  const target = resolve(dir);
  const r = syncRepos(target, readRepoList(list), (s) => console.log(c.dim(s)));
  console.log(`${r.cloned.length} cloned, ${r.updated.length} updated, ${r.failed.length} failed.`);
  scan([target]);
  await checkAll(db);
  if (r.failed.length) process.exitCode = 1;
}

/** Live with a reviewed finding for now: named projects, the advisories it has today, a reason, an expiry. */
function accept(target?: string) {
  const rules = loadAcceptances(db);
  if (!target) {
    if (!rules.length) return console.log("Nothing accepted.");
    const now = new Date();
    for (const a of rules) {
      const expired = new Date(a.expires) <= now;
      console.log(`${c.bold(a.name + (a.version ? "@" + a.version : ""))}  ${expired ? c.red("EXPIRED " + a.expires.slice(0, 10)) : c.dim("until " + a.expires.slice(0, 10))}  ${c.cyan(a.projects.join(", "))}`);
      console.log(`  ${a.reason}`);
      console.log(c.dim(`  ${a.vulnIds.join(", ")}`));
    }
    return;
  }
  const [name, version] = splitTarget(target);
  const reason = flagValue("--reason")?.trim();
  const projects = flagValue("--project")?.split(",").map((p) => p.trim()).filter(Boolean) ?? [];
  const days = Number(flagValue("--days") ?? 90);
  if (!reason) return fail("A reason is required: --reason \"why this is OK for now\"");
  if (!projects.length) return fail("Say which projects: --project a,b");
  if (!(days > 0)) return fail("--days must be a positive number");
  const matches = findings(db, { includeDev: true, includeAccepted: true }).filter(
    (f) => f.name === name && (!version || f.version === version) && f.hits.some((h) => projects.includes(h.project)),
  );
  if (matches.some((f) => f.vulnId.startsWith("MAL-"))) return fail(`${target} is flagged as malicious (MAL-*): that can't be accepted. Remove it.`);
  if (!matches.length) return fail(`No open finding for ${target} in ${projects.join(", ")}.`);
  const key = (a: Acceptance) => `${a.name}@${a.version ?? ""}|${[...a.projects].sort().join(",")}`;
  const entry: Acceptance = {
    name, ...(version ? { version } : {}), vulnIds: [...new Set(matches.map((f) => f.vulnId))], projects, reason,
    acceptedAt: new Date().toISOString(), expires: new Date(Date.now() + days * 86_400_000).toISOString(),
  };
  setSetting("accepted", JSON.stringify([...rules.filter((a) => key(a) !== key(entry)), entry]));
  console.log(`Accepted ${c.bold(target)} in ${projects.join(", ")} until ${entry.expires.slice(0, 10)} (${entry.vulnIds.length} advisories).`);
}

function unaccept(target?: string) {
  if (!target) return fail("Which package? mycelium unaccept <pkg[@ver]> [--project a,b]");
  const [name, version] = splitTarget(target);
  const only = flagValue("--project")?.split(",");
  const rules = loadAcceptances(db);
  const kept = rules.flatMap((a) => {
    if (a.name !== name || (version && a.version !== version)) return [a];
    const projects = only ? a.projects.filter((p) => !only.includes(p)) : [];
    return projects.length ? [{ ...a, projects }] : [];
  });
  setSetting("accepted", JSON.stringify(kept));
  console.log(`Removed ${rules.length - kept.length} acceptance(s) for ${target}${only ? ` (projects: ${only.join(", ")})` : ""}.`);
}

function fail(message: string) {
  console.error(c.red(message));
  process.exitCode = 1;
}

/** Folders left out of every scan. They stay on disk; findings from them just stop counting. */
function ignore(folders: string[], remove = false) {
  let list: string[] = JSON.parse(getSetting("ignored") ?? "[]");
  const given = folders.map((f) => resolve(f));
  if (given.length) {
    list = remove ? list.filter((p) => !given.includes(p)) : [...new Set([...list, ...given])];
    setSetting("ignored", JSON.stringify(list));
    console.log(c.dim("Takes effect on the next `mycelium scan`."));
  }
  console.log(list.length ? list.join("\n") : "Nothing ignored.");
}

function scan(roots: string[]) {
  const remembered: string[] = JSON.parse(getSetting("roots") ?? "null") ?? [];
  const list = roots.length ? roots.map((r) => resolve(r)) : remembered.length ? remembered : [process.cwd()];
  // Scanning one folder adds it to what's remembered; it never replaces it. (`scan werbosLLM` once used to shrink
  // every later `fix --all` refresh down to that one folder, so the rest were planned from stale scans.)
  setSetting("roots", JSON.stringify(mergeRoots(remembered, list)));
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
  const accepted = acceptedCount(db, { includeDev: flags.has("--dev") });
  if (accepted) console.log(c.dim(`${accepted} accepted, not counted above (\`mycelium accept\` lists them).`));
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
  // Counts come from findings(), so accepted items aren't "open" here either.
  const open = new Map<string, Set<string>>();
  for (const f of findings(db)) for (const h of f.hits) open.set(h.project, (open.get(h.project) ?? new Set()).add(f.vulnId));
  const rules = loadAcceptances(db);
  const accepted = new Map<string, Set<string>>();
  for (const f of findings(db, { includeAccepted: true })) {
    for (const h of f.hits) if (rules.some((a) => acceptanceCovers(a, f, h.project))) accepted.set(h.project, (accepted.get(h.project) ?? new Set()).add(f.vulnId));
  }
  const rows = (db.prepare(`
    SELECT pr.id, pr.name, pr.exposure,
      (SELECT count(DISTINCT u.package_id) FROM uses u JOIN components c ON c.id = u.component_id WHERE c.project_id = pr.id) AS pkgs
    FROM projects pr`).all() as any[])
    .map((r) => ({ ...r, vulns: open.get(r.name)?.size ?? 0, accepted: accepted.get(r.name)?.size ?? 0 }))
    .sort((x, y) => y.vulns - x.vulns || x.name.localeCompare(y.name));
  const infraStmt = db.prepare("SELECT DISTINCT kind, value FROM infra WHERE project_id = ? AND kind IN ('host','domain','distribution')");
  for (const r of rows) {
    const where = (infraStmt.all(r.id) as any[]).map((i) => i.value).join(", ");
    const v = r.vulns ? c.red(`${r.vulns} vulns`.padEnd(9)) : c.green("clean".padEnd(9));
    const acc = r.accepted ? c.dim(` (${r.accepted} accepted)`) : "";
    console.log(`${c.bold(r.name.padEnd(28))} ${String(r.pkgs).padStart(5)} pkgs  ${v}${acc} ${c.cyan(r.exposure.padEnd(11))} ${c.dim(where)}`);
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
  if (r.failed.length) console.log(c.red(`\n✗ failed ${r.failed.length}:`) + "\n  " + r.failed.map((f) => `${f.fix.name}: ${errLine(f.error)}`).join("\n  "));
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
  // --stream: machine-readable progress for the dashboard, which runs fixes as a separate process.
  const stream = flags.has("--stream");
  const r = applyFixes(db, plan, {
    allowMajor: flags.has("--major"), verify: flags.has("--verify"),
    only: flagValue("--only")?.split(","), dryRun: flags.has("--dry-run"), pr: flags.has("--pr"),
    ...(stream ? { onLog: (l: string) => console.log("@log " + l.split("\n")[0]) } : {}),
  });
  if (stream) console.log("@result " + JSON.stringify(r));
  else printApply(r);
  if (r.applied.length && !flags.has("--dry-run")) {
    await checkAll(db);
    console.log(c.dim("\nRe-checked OSV. `mycelium projects` shows the new counts."));
  }
}

/**
 * `fix --all`: every project, headless. Refresh → plan → apply (verify + PR) one at a time → summary.
 * A failure in one project never stops the rest. Writes a JSON report for agents/skills to read.
 */
async function fixAll() {
  const apply = flags.has("--apply");
  if (!flags.has("--no-refresh")) {
    const roots = JSON.parse(getSetting("roots") ?? "[]");
    if (!roots.length) return console.log("Run `mycelium scan <folders>` first.");
    const { syncPrs, pullBases } = await import("./prs.ts");
    // Pull GitHub's main/master first (fast-forward only), so fixes already merged there aren't planned or PR'd again.
    if (!flags.has("--no-pull")) {
      console.log(c.dim("pulling default branches (fast-forward only)…"));
      const onlyPaths = flagValue("--project") ? new Set((db.prepare("SELECT name, path FROM projects").all() as { name: string; path: string }[])
        .filter((p) => flagValue("--project")!.split(",").includes(p.name)).map((p) => p.path)) : undefined;
      const pulled = await pullBases(db, (s) => console.log(c.dim("   " + s)), onlyPaths);
      console.log(c.dim(`pulled ${pulled.pulled.length} repo(s)${pulled.refused.length ? `, ${pulled.refused.length} left alone` : ""}`));
    }
    console.log(c.dim(`refreshing: scanning ${roots.join(", ")}, checking OSV, syncing PRs…`));
    scanRoots(db, roots);
    await checkAll(db);
    await syncPrs(db);
  }
  const allowMajor = flags.has("--major");
  const only = flagValue("--project")?.split(",");
  const projects = (db.prepare("SELECT name FROM projects ORDER BY name").all() as { name: string }[])
    .map((p) => p.name).filter((n) => !only || only.includes(n));

  type Row = { project: string; status: "fixed" | "pr" | "nothing" | "manual-only" | "failed" | "verify-failed" | "planned";
    autoFixable: number; fixed: string[]; prs: string[]; failed: string[]; manual: number; skippedNotes: string[]; branch: string | null; error?: string };
  const rows: Row[] = [];
  // One stable progress line per project ("[i/N] name · status · PR urls") so a skill/agent can stream it.
  const progress = (i: number, r: Row | undefined, name: string) => {
    const detail = !r ? "" : r.prs.length ? r.prs.join(" ") + (r.error ? ` · ${r.error}` : "") : r.status === "manual-only" ? `${r.manual} need a human` :
      r.status === "planned" ? `${r.autoFixable} auto` : r.status === "verify-failed" ? `build/test broke, branch ${r.branch} kept` :
      r.status === "fixed" ? `committed on ${r.branch}${r.error ? ` · ${r.error}` : ", no PR"}` : r.status === "failed" ? (r.error ?? r.failed.join("; ")).slice(0, 160) : "";
    console.log(`[${i}/${projects.length}] ${name} · ${r?.status ?? "failed"}${detail ? " · " + detail : ""}`);
  };
  for (const [idx, name] of projects.entries()) try {
    let plan: FixPlan;
    try {
      plan = planFixes(db, name, { minSeverity: flagValue("--min")?.toUpperCase(), includeDev: flags.has("--dev") });
    } catch (e) {
      rows.push({ project: name, status: "failed", autoFixable: 0, fixed: [], prs: [], failed: [], manual: 0, skippedNotes: [], branch: null, error: (e as Error).message });
      continue;
    }
    const auto = plan.fixes.filter((f) => f.strategy !== "manual" && (allowMajor || !f.breaking));
    const manual = plan.fixes.length - auto.length;
    const row: Row = { project: name, status: "nothing", autoFixable: auto.length, fixed: [], prs: [], failed: [], manual, skippedNotes: [], branch: null };
    rows.push(row);
    if (!plan.fixes.length) continue;
    if (!auto.length) { row.status = "manual-only"; continue; }
    if (!apply) {
      row.status = "planned";
      console.log(`${c.bold(name.padEnd(28))} ${c.green(`${auto.length} auto`)}${manual ? c.dim(` · ${manual} manual`) : ""}  ${c.dim(auto.map((f) => `${f.name} ${f.from}→${f.to}`).join(", ").slice(0, 120))}`);
      continue;
    }
    console.log(`\n[${idx + 1}/${projects.length}] ${name} · working · ${auto.length} auto-fixable (install/build/test may take minutes)`);
    try {
      const r = applyFixes(db, plan, { allowMajor, verify: !flags.has("--no-verify"), pr: !flags.has("--no-pr"),
        onLog: (l) => console.log(c.dim("   " + l.split("\n")[0])) });
      row.fixed = r.fixed;
      row.prs = r.prs.map((p) => p.url);
      row.failed = r.failed.map((f) => `${f.fix.name}: ${errLine(f.error)}`);
      row.skippedNotes = [...new Set(r.skipped.filter((s) => /open PR|already fixed|worktree of a repo|not present/.test(s.reason)).map((s) => `${s.fix.name}: ${s.reason}`))];
      row.branch = r.branch;
      const verifyFailed = r.verifyFailedRepos.length > 0;
      // Applied but the package manager kept the old version: that's a failure to report, not "nothing".
      if (!r.fixed.length && r.stillVulnerable.length) row.failed.push(...r.stillVulnerable.map((s) => `${s}: still locked at the vulnerable version after the upgrade`));
      const human = r.skipped.filter((s) => s.human);
      row.manual += human.length;
      row.status = row.prs.length ? "pr" : verifyFailed && r.committed ? "verify-failed" : r.fixed.length ? "fixed" : row.failed.length ? "failed" : human.length ? "manual-only" : "nothing";
      const notes: string[] = [];
      if (verifyFailed) notes.push(`build/test broke in ${r.verifyFailedRepos.map((p) => relative(plan.projectPath, p) || basename(p)).join(", ")}: branch kept, no PR`);
      if (r.noPr.length) notes.push(`no PR: ${r.noPr.join("; ")}`);
      if (row.status === "failed") notes.push(row.failed.join("; "));
      if (notes.length) row.error = notes.join(" · ");
    } catch (e) {
      row.status = "failed";
      row.error = errLine((e as Error).message);
      console.log(c.red(`   ✗ ${row.error}`));
    }
  } finally {
    progress(idx + 1, rows.find((r) => r.project === name), name);
  }

  if (apply) {
    await checkAll(db);
    const { syncPrs } = await import("./prs.ts");
    await syncPrs(db);
  }
  const acted = rows.filter((r) => r.status !== "nothing");
  console.log(c.bold(`\n${apply ? "Fix-all summary" : "Fix-all plan (dry run; add --apply)"}`));
  const icon: Record<Row["status"], string> = { pr: "⇪", fixed: "✓", "verify-failed": "✗", failed: "✗", "manual-only": "·", planned: "→", nothing: "✓" };
  for (const r of acted) {
    const detail = r.status === "pr" ? r.prs.join(" ") + (r.error ? ` · ${r.error}` : "") : r.status === "manual-only" ? `${r.manual} need a human` : r.status === "planned" ? `${r.autoFixable} auto` :
      r.status === "verify-failed" ? `build/test broke: branch ${r.branch} kept, no PR` : r.status === "fixed" ? `committed on ${r.branch} (${r.error ?? "no PR"})` :
      r.error ?? r.failed.join("; ") ?? "";
    console.log(`${icon[r.status]} ${r.project.padEnd(28)} ${r.status.padEnd(14)} ${c.dim(detail.slice(0, 200))}`);
  }
  const clean = rows.length - acted.length;
  console.log(c.dim(`\n${clean} project(s) had nothing to fix.`));
  const dir = join(homedir(), ".mycelium");
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `fix-all-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
  writeFileSync(file, JSON.stringify({ apply, allowMajor, at: new Date().toISOString(), rows }, null, 2));
  console.log(c.dim(`report: ${file}`));
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
  ${c.cyan("repos")}                GitHub repos behind your projects, one owner/name per line (input for sync).
  ${c.cyan("sync")} <dir> --list <file>  Headless: clone or fast-forward those repos into <dir>, then scan and check.
  ${c.cyan("accept")} <pkg[@ver]>      Live with a reviewed finding: --project a,b --reason "…" [--days 90]. New advisories
                       still show. No args: list them. \`unaccept\` undoes it.
  ${c.cyan("ignore")} [folders…]    Leave folders out of every scan (snapshots, backups). No args: list them. \`unignore\` undoes it.
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
  ${c.cyan("fix --all")}            Every project, headless: fast-forward main/master from GitHub, refresh, then plan
                       (dry) or --apply: build/test + PR per repo, one at a time.
                       --major | --min high | --project a,b | --no-pr | --no-verify | --no-pull
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
  case "repos": console.log((await import("./sync.ts")).knownRepos(db).join("\n")); break;
  case "sync": await sync(args[0]); break;
  case "accept": accept(args[0]); break;
  case "unaccept": unaccept(args[0]); break;
  case "ignore": ignore(args); break;
  case "unignore": ignore(args, true); break;
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
  case "fix": flags.has("--all") ? await fixAll() : args[0] ? await fix(args[0]) : console.log("usage: mycelium fix <project> [--apply] [--verify] [--pr] [--major] [--min high] [--only a,b]"); break;
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
