// The fix engine: turn findings into a concrete plan, apply it on a git branch, then re-scan to prove what got fixed.
//
// Safety rules:
//   - Never touches your working folder: fixes run in a throwaway git worktree on a new branch
//     `mycelium/fix-<timestamp>`, cut from whatever you have checked out. Uncommitted work is irrelevant.
//   - The result is committed to that branch (the worktree is deleted after). Push + PR only when asked; never merges.
//   - Major-version bumps are planned but skipped unless allowMajor (they can break your code).
//   - Success is measured by re-reading the lockfiles, not by trusting that a command exited 0.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { findings, type Finding } from "./graph.ts";
import { compareVersions, severityRank } from "./osv.ts";
import { defaultBranch } from "./prs.ts";
import { scanProject } from "./scan.ts";

export type Strategy =
  | "bump-direct" // edit the version in the manifest
  | "override" // force a transitive version (npm overrides / pnpm.overrides / yarn resolutions)
  | "cargo-update" // cargo update -p name@from --precise to
  | "cargo-parent" // a parent crate pins it to an old major: cargo update the parent(s) within their semver range
  | "dotnet-add" // dotnet add package (also pins transitives)
  | "pip-pin" // rewrite name==version in requirements
  | "uv-upgrade" // uv lock --upgrade-package
  | "go-get" // go get module@vX
  | "gradle-edit" // rewrite "g:a:version" in build.gradle
  | "manual"; // nothing safe to automate

export interface PlannedFix {
  project: string;
  projectPath: string;
  component: string; // lockfile path, relative to project
  ecosystem: string;
  name: string;
  from: string;
  to: string | null;
  direct: boolean;
  severity: string;
  vulns: string[];
  breaking: boolean; // major bump (or 0.x minor bump)
  strategy: Strategy;
  note: string;
}

export interface FixPlan {
  project: string;
  projectPath: string;
  fixes: PlannedFix[];
}

const major = (v: string) => {
  const [a, b] = v.split(".").map(Number);
  return a === 0 ? `0.${b}` : String(a);
};

// ---------------------------------------------------------------- plan

export function planFixes(db: DatabaseSync, project: string, opts: { minSeverity?: string; includeDev?: boolean } = {}): FixPlan {
  const row = db.prepare("SELECT path FROM projects WHERE name = ? OR path = ?").get(project, project) as { path: string } | undefined;
  if (!row) throw new Error(`No project named "${project}". Run \`mycelium projects\` to list them.`);
  const min = severityRank(opts.minSeverity ?? "LOW");

  // Group findings by (component, package) so one upgrade clears every advisory on that version.
  const groups = new Map<string, { f: Finding[]; hit: Finding["hits"][number] }>();
  for (const f of findings(db, { includeDev: opts.includeDev })) {
    if (severityRank(f.severity) < min && f.severity !== "UNKNOWN") continue;
    for (const h of f.hits) {
      if (h.projectPath !== row.path) continue;
      const k = `${h.component}|${f.ecosystem}|${f.name}|${f.version}`;
      const g = groups.get(k) ?? { f: [], hit: h };
      if (!g.f.some((x) => x.vulnId === f.vulnId)) g.f.push(f);
      if (h.direct) g.hit = h;
      groups.set(k, g);
    }
  }

  const fixes: PlannedFix[] = [];
  for (const { f, hit } of groups.values()) {
    const first = f[0];
    const fixable = f.filter((x) => x.fixed);
    // Highest "fixed" across advisories clears all of them.
    const to = fixable.length ? fixable.map((x) => x.fixed!).sort(compareVersions).at(-1)! : null;
    const worst = f.map((x) => x.severity).sort((a, b) => severityRank(b) - severityRank(a))[0];
    const base: PlannedFix = {
      project: hit.project, projectPath: hit.projectPath, component: hit.component, ecosystem: first.ecosystem,
      name: first.name, from: first.version, to, direct: hit.direct, severity: worst,
      vulns: f.map((x) => x.cve ?? x.vulnId), breaking: !!to && major(to) !== major(first.version),
      strategy: "manual", note: "",
    };
    if (!to) {
      fixes.push({ ...base, note: "no fixed version published: replace the package or wait" });
      continue;
    }
    if (fixable.length < f.length) base.note = `${f.length - fixable.length} advisory(ies) have no fix yet. `;
    // A beta/RC isn't a fix you ship: hold it for a human unless you're already on prereleases.
    if (isPrerelease(to) && !isPrerelease(first.version)) {
      fixes.push({ ...base, note: base.note + `the only fixed release is a prerelease (${to}): wait for the stable release, or upgrade by hand if you accept a beta` });
      continue;
    }
    fixes.push(chooseStrategy(base));
  }
  fixes.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.name.localeCompare(b.name));
  return { project: fixes[0]?.project ?? project, projectPath: row.path, fixes };
}

export function isPrerelease(v: string): boolean {
  return /[-.](alpha|beta|rc|cr|pre|preview|dev|snapshot|canary|next|nightly|m|ea)\d*\b/i.test(v) || /\d(a|b|rc)\d+$/i.test(v);
}

function chooseStrategy(fx: PlannedFix): PlannedFix {
  const dir = join(fx.projectPath, dirname(fx.component));
  const lock = fx.component.split("/").pop()!;
  switch (fx.ecosystem) {
    case "npm": {
      const manifest = readJson(join(dir, "package.json"));
      const field = manifest && ["dependencies", "devDependencies", "optionalDependencies"].find((k) => manifest[k]?.[fx.name]);
      // The manifest is the truth: npm refuses to override a package you declare yourself (EOVERRIDE), so a declared
      // package on the same major line is bumped directly. A declared one on another major means this copy is nested.
      const declared = field ? String(manifest[field][fx.name]).match(/\d+(\.\d+)*/)?.[0] : undefined;
      if (field && (fx.direct || (declared && major(declared) === major(fx.from)))) {
        return { ...fx, direct: true, strategy: "bump-direct", note: fx.note + `set ${field}.${fx.name} to ^${fx.to}` };
      }
      const key = lock === "yarn.lock" ? fx.name : `${fx.name}@^${major(fx.from)}`;
      return { ...fx, strategy: "override", note: fx.note + `force ${key} → ^${fx.to} (transitive)` };
    }
    case "crates.io":
      // `cargo update --precise` can only move within ranges every dependent accepts, so a semver-major jump
      // needs a Cargo.toml edit (direct) or a newer parent crate (transitive). Don't promise what cargo can't do.
      if (fx.breaking && fx.direct) return { ...fx, note: fx.note + `edit Cargo.toml: ${fx.name} = "${fx.to}" (major bump, check the changelog)` };
      if (fx.breaking) {
        // Often a newer *compatible* release of the parent already moved on (tauri-plugin-updater 2.14.1 → zip 9,
        // plist 1.10 → quick-xml 0.41). Updating the parent within its own range doesn't touch your code, so it
        // isn't a major bump for you. If no such release exists, apply leaves it for a human.
        const parents = cargoDependents(safeRead(join(dir, "Cargo.lock")) ?? "", [`${fx.name}@${fx.from}`]);
        return { ...fx, breaking: false, strategy: "cargo-parent",
          note: fx.note + `a parent crate pins ${fx.name} to ${major(fx.from)}.x: cargo update ${parents.map((p) => p.split("@")[0]).join(", ") || "its parent"} within semver, to pick up a release that dropped it` };
      }
      // Newest compatible, not exactly `to`: crate families (tauri + tauri-runtime …) only line up on matching releases.
      return { ...fx, strategy: "cargo-update", note: fx.note + `cargo update -p ${fx.name}@${fx.from} (newest ${major(fx.from)}.x, ≥ ${fx.to})` };
    case "NuGet": {
      const proj = lock.endsWith("proj") ? lock : readdirSync(dir).find((f) => /\.(cs|fs|vb)proj$/.test(f));
      return proj
        ? { ...fx, strategy: "dotnet-add", note: fx.note + `dotnet add ${proj} package ${fx.name} --version ${fx.to}` }
        : { ...fx, note: fx.note + "no project file next to the lockfile" };
    }
    case "PyPI":
      if (/^requirements.*\.txt$/.test(lock)) return { ...fx, strategy: "pip-pin", note: fx.note + `pin ${fx.name}==${fx.to}` };
      if (lock === "uv.lock") return { ...fx, strategy: "uv-upgrade", note: fx.note + `uv lock --upgrade-package ${fx.name}==${fx.to}` };
      return { ...fx, note: fx.note + `bump ${fx.name} to ${fx.to} in pyproject.toml, then re-lock` };
    case "Go":
      return { ...fx, strategy: "go-get", note: fx.note + `go get ${fx.name}@v${fx.to} && go mod tidy` };
    case "Maven": {
      const text = safeRead(join(fx.projectPath, fx.component));
      return text?.includes(`${fx.name}:${fx.from}`)
        ? { ...fx, strategy: "gradle-edit", note: fx.note + `${fx.name}:${fx.from} → ${fx.to}` }
        : { ...fx, note: fx.note + `bump ${fx.name} to ${fx.to} (version lives in a catalog/variable)` };
    }
  }
  return fx;
}

// ---------------------------------------------------------------- apply

export interface ApplyOptions {
  allowMajor?: boolean;
  /** @deprecated fixes are always committed to their branch now (they run in a throwaway worktree). */
  commit?: boolean;
  verify?: boolean;
  only?: string[]; // limit to these package names
  dryRun?: boolean;
  pr?: boolean; // commit, push the branch, open a GitHub PR (implies commit)
  /** Called with each log line as it happens (a big project can run for an hour; don't make the caller wait for the end). */
  onLog?: (line: string) => void;
}

export interface ApplyResult {
  branch: string | null;
  repos: string[];
  applied: PlannedFix[];
  /** human: tried, and there's no automatic fix yet (e.g. no compatible parent release): counts as manual, not failed. */
  skipped: { fix: PlannedFix; reason: string; human?: boolean }[];
  failed: { fix: PlannedFix; error: string }[];
  fixed: string[]; // "name@from" that no longer appear vulnerable after re-scan
  stillVulnerable: string[];
  /** preexisting: the same command also fails on the branch you started from, so the upgrade didn't cause it. */
  verify: { dir: string; command: string; ok: boolean; output: string; preexisting?: boolean; baseBroken?: boolean }[];
  committed: boolean;
  prs: { repo: string; url: string; base: string }[];
  /** Repos that got a committed branch but can't get a PR (no GitHub remote, empty repo, push denied, duplicate branch). */
  noPr: string[];
  /** Repos whose build/test broke because of the upgrade: their branch is kept, no PR. Other repos still get theirs. */
  verifyFailedRepos: string[];
  log: string[];
}

export function applyFixes(db: DatabaseSync, plan: FixPlan, opts: ApplyOptions = {}): ApplyResult {
  // git reports real paths (/private/var/…, resolved symlinks); compare like with like.
  const real = (p: string) => {
    try {
      return realpathSync(p);
    } catch {
      return p;
    }
  };
  plan = { ...plan, projectPath: real(plan.projectPath), fixes: plan.fixes.map((f) => ({ ...f, projectPath: real(f.projectPath) })) };
  const res: ApplyResult = { branch: null, repos: [], applied: [], skipped: [], failed: [], fixed: [], stillVulnerable: [], verify: [], committed: false, prs: [], noPr: [], verifyFailedRepos: [], log: [] };
  const log = (s: string) => {
    res.log.push(s);
    opts.onLog?.(s);
  };

  // 1. Decide what we'll touch.
  const todo: PlannedFix[] = [];
  // Already in an open Mycelium PR? Don't open a second one for the same thing (as of the last PR sync).
  const inOpenPr = new Map<string, number>();
  for (const r of db.prepare(`SELECT f.project_path, f.component, f.name, f.version, p.number FROM pr_fixes f
      JOIN prs p ON p.id = f.pr_id WHERE p.state = 'OPEN'`).all() as any[]) {
    inOpenPr.set(`${real(r.project_path)}|${r.component}|${r.name}@${r.version}`, r.number);
  }
  for (const fx of plan.fixes) {
    if (opts.only?.length && !opts.only.includes(fx.name)) continue;
    const openPrNo = inOpenPr.get(`${fx.projectPath}|${fx.component}|${fx.name}@${fx.from}`);
    if (openPrNo && !opts.dryRun) res.skipped.push({ fix: fx, reason: `already fixed in open PR #${openPrNo}: merge or close that one first` });
    else if (fx.strategy === "manual") res.skipped.push({ fix: fx, reason: fx.note || "needs a human" });
    else if (fx.breaking && !opts.allowMajor) res.skipped.push({ fix: fx, reason: `major bump ${fx.from} → ${fx.to}: rerun with allowMajor after checking the changelog` });
    else todo.push(fx);
  }
  if (!todo.length) {
    log("Nothing safe to apply automatically.");
    return res;
  }

  // 2. Every touched repo gets a throwaway git worktree on a new branch, cut from whatever you have checked out.
  //    Your working folder is never touched: uncommitted work doesn't block fixes, and you never end up on our branch.
  const repoOf = new Map<string, string>(); // absolute component dir -> repo root
  for (let i = todo.length - 1; i >= 0; i--) {
    const fx = todo[i];
    const dir = join(fx.projectPath, dirname(fx.component));
    const root = existsSync(dir) ? git(dir, ["rev-parse", "--show-toplevel"]) : null;
    if (root) {
      repoOf.set(dir, root);
      continue;
    }
    // One stray folder (a backup copy, an unversioned experiment) shouldn't block every other repo in the project.
    res.skipped.push({ fix: fx, human: true, reason: `${relative(fx.projectPath, dir) || dir} isn't in a git repo: fixes need git so they can be reviewed and undone` });
    todo.splice(i, 1);
  }
  const noGit = [...new Set(res.skipped.filter((s) => s.reason.includes("isn't in a git repo")).map((s) => s.reason.split(" isn't")[0]))];
  if (noGit.length) log(`skipping ${noGit.length} folder(s) that aren't in git: ${noGit.join(", ")}`);
  if (!todo.length) {
    log("Nothing left to apply: every fixable folder is outside git.");
    return res;
  }
  res.repos = [...new Set(repoOf.values())];
  const branch = `mycelium/fix-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "")}`;
  if (opts.dryRun) {
    log(`[dry run] would create branch ${branch} in a worktree of ${res.repos.join(", ")}`);
    for (const fx of todo) log(`[dry run] ${fx.strategy}: ${fx.note}`);
    res.applied = todo;
    return res;
  }

  const wt = new Map<string, { path: string; base: string; target: string; branch: string; reused?: string }>();
  const committedRepos: string[] = []; // repo -> worktree
  try {
    const prTargets = new Map<string, string>(), dropRepos = new Set<string>();
    const noPr = new Map<string, string>(); // repo -> why it can't get a PR (fix still lands on a local branch)
    for (const repo of res.repos) {
      const current = git(repo, ["branch", "--show-current"]) || git(repo, ["rev-parse", "HEAD"])!;
      // `base` = what the fix is cut from and compared against; `target` = the branch a PR goes into.
      // For a PR they must be the same branch on GitHub. Cutting from a local-only branch while the PR targets
      // main means main never looks fixed from here, and every click opens the same PR again.
      let base = current, target = current, start = "HEAD";
      // No GitHub to PR into (no remote, not GitHub, empty repo): still fix it on a local branch, just no PR.
      const remote = opts.pr ? git(repo, ["remote", "get-url", "origin"]) : null;
      const def = remote && /github\.com[:/]/.test(remote) ? defaultBranch(repo) : null;
      if (opts.pr && !def) {
        const why = !remote ? "no git remote" : !/github\.com[:/]/.test(remote) ? `origin isn't GitHub (${remote})` : "the GitHub repo has no branches yet (push one first)";
        noPr.set(repo, `${relative(plan.projectPath, repo) || basename(repo)}: ${why}`);
        log(`no PR possible for ${relative(plan.projectPath, repo) || basename(repo)}: ${why}. Fixing on a local branch from ${current}`);
      }
      if (opts.pr && def) {
        target = /^[0-9a-f]{40}$/.test(current) || !git(repo, ["ls-remote", "--heads", "origin", current]) ? def : current;
        // A branch with nothing beyond the default is already merged: a PR into it would never reach what you ship.
        if (target !== def && git(repo, ["fetch", "-q", "origin", def, target]) !== null &&
            git(repo, ["rev-list", "--count", `origin/${def}..origin/${target}`]) === "0") {
          log(`PR mode: ${target} has nothing that isn't already on ${def}, so the PR goes into ${def}`);
          target = def;
        }
        if (git(repo, ["fetch", "-q", "origin", target]) === null || !git(repo, ["rev-parse", "--verify", "-q", `origin/${target}`])) {
          throw new Error(`couldn't fetch origin/${target} from GitHub`);
        }
        base = start = `origin/${target}`;
        if (target !== current) log(`PR mode: not using ${current}, so the PR goes into ${target} and is built on origin/${target}`);
        else {
          const ahead = Number(git(repo, ["rev-list", "--count", `${start}..HEAD`]) ?? 0);
          const behind = Number(git(repo, ["rev-list", "--count", `HEAD..${start}`]) ?? 0);
          log(`PR mode: building on ${start}` + (ahead ? `. Note: your local ${current} has ${ahead} unpushed commit(s), which are NOT included` : "") +
            (behind ? `${ahead ? ";" : ". Note:"} it's ${behind} commit(s) behind GitHub` : ""));
        }
      }
      // Several folders can be worktrees of one repo. Fixing them all into the same GitHub branch = duplicate PRs.
      const common = realpathSync(resolve(repo, git(repo, ["rev-parse", "--git-common-dir"]) ?? ".git"));
      if (opts.pr && prTargets.has(`${common}|${target}`)) {
        log(`skipping ${relative(plan.projectPath, repo) || repo}: same repo as ${prTargets.get(`${common}|${target}`)}, and its PR into ${target} already covers it`);
        dropRepos.add(repo);
        continue;
      }
      prTargets.set(`${common}|${target}`, relative(plan.projectPath, repo) || repo);
      const path = worktreeDir(repo, "mycelium-wt-");
      // Unique per repo: folders that are worktrees of one repo share branch names, and so do two clicks in a minute.
      let b = branch;
      for (let n = 2; git(repo, ["rev-parse", "--verify", "-q", `refs/heads/${b}`]); n++) b = `${branch}-${n}`;
      gitOrThrow(repo, ["worktree", "add", "-b", b, path, start]);
      wt.set(repo, { path, base, target, branch: b });
      log(`working in a separate worktree on ${b}${res.repos.length > 1 ? ` in ${relative(plan.projectPath, repo) || "."}` : ""} (from ${start === "HEAD" ? base : start}); your checkout is untouched`);
    }

    for (let i = todo.length - 1; i >= 0; i--) {
      const repo = repoOf.get(join(todo[i].projectPath, dirname(todo[i].component)))!;
      if (dropRepos.has(repo)) {
        res.skipped.push({ fix: todo[i], reason: `${relative(plan.projectPath, repo)} is a worktree of a repo already being fixed into the same branch` });
        todo.splice(i, 1);
      }
    }

    // The plan came from your folder; the worktree may differ (e.g. upstream already removed a package).
    for (const [repo, { path }] of wt) {
      const scan = scanProject(path);
      const present = new Set(scan.components.flatMap((c) => c.packages.map((p) => `${c.path}|${p.name}@${p.version}`)));
      for (let i = todo.length - 1; i >= 0; i--) {
        const fx = todo[i];
        if (repoOf.get(join(fx.projectPath, dirname(fx.component))) !== repo) continue;
        const rel = relative(repo, join(fx.projectPath, fx.component));
        if (present.has(`${rel}|${fx.name}@${fx.from}`)) continue;
        // A gitignored lockfile (EnvSync's src-tauri/Cargo.lock) is only on your disk: a branch can't change it,
        // and "already fixed upstream" would be a lie.
        if (git(repo, ["ls-files", "--error-unmatch", rel]) === null) {
          res.skipped.push({ fix: fx, human: true, reason: `${rel} isn't committed (gitignored?), so a branch can't fix it: commit the lockfile, or update it locally` });
        } else res.skipped.push({ fix: fx, reason: `not present on ${wt.get(repo)!.base} upstream (already removed or upgraded there)` });
        todo.splice(i, 1);
      }
    }
    const untracked = [...new Set(res.skipped.filter((s) => s.human && s.reason.includes("isn't committed")).map((s) => s.reason.split(" isn't")[0]))];
    if (untracked.length) log(`${untracked.join(", ")}: not committed to git, so these fixes need a human (commit the lockfile, or update it locally)`);
    if (!todo.length && wt.size && res.skipped.some((s) => s.reason.startsWith("not present on"))) {
      const [, w] = [...wt][0];
      log(w.target && w.base === `origin/${w.target}` && w.target !== (git(res.repos[0], ["branch", "--show-current"]) ?? "")
        ? `✅ already fixed on GitHub's ${w.target}. Your folder is on ${git(res.repos[0], ["branch", "--show-current"])}, which doesn't have it yet: ` +
          `merge ${w.target} into it (\`git merge origin/${w.target}\`) or switch to ${w.target}, then Rescan`
        : `✅ already fixed on ${w.base}: pull (⬇ Pull or \`git pull\`), then Rescan`);
    }
    res.branch = [...wt.values()].map((w) => w.branch).join(", ");
    const inWorktree = (absDir: string) => {
      const repo = repoOf.get(absDir)!;
      return join(wt.get(repo)!.path, relative(repo, absDir));
    };

    // 3. Apply, grouped by lockfile so each one is re-resolved once.
    const legacyPeers = new Set<string>(); // component dirs (your paths) whose npm tree only resolves with --legacy-peer-deps
    const byComponent = new Map<string, PlannedFix[]>();
    for (const fx of todo) byComponent.set(fx.component, [...(byComponent.get(fx.component) ?? []), fx]);
    for (const [component, fxs] of byComponent) {
      const dir = inWorktree(join(plan.projectPath, dirname(component)));
      const { ok, failed, human, legacy } = applyComponent(dir, component.split("/").pop()!, fxs, log);
      if (legacy) legacyPeers.add(join(plan.projectPath, dirname(component)));
      res.applied.push(...ok);
      res.skipped.push(...(human ?? []));
      for (const f of failed) {
        res.failed.push(f);
        log(`✗ ${f.fix.name}: ${errLine(f.error)}`);
      }
    }

    // 4. Re-read the lockfiles in the worktree: that's the source of truth, not the exit code.
    for (const [repo, { path }] of wt) {
      const scan = scanProject(path);
      const have = new Set(scan.components.flatMap((c) => c.packages.map((p) => `${c.path}|${p.name}@${p.version}`)));
      for (const fx of res.applied.filter((f) => repoOf.get(join(f.projectPath, dirname(f.component))) === repo)) {
        const label = `${fx.name}@${fx.from}`;
        if (have.has(`${relative(repo, join(fx.projectPath, fx.component))}|${label}`)) res.stillVulnerable.push(`${label} (${fx.component})`);
        else res.fixed.push(`${label} → ${fx.to} (${fx.component})`);
      }
    }

    // 5. Optional build/test, in the worktree. Rust reuses your target/ so it doesn't rebuild the world.
    if (opts.verify && res.fixed.length) {
      for (const absDir of new Set(res.applied.map((fx) => join(plan.projectPath, dirname(fx.component))))) {
        const dir = inWorktree(absDir);
        const repo = repoOf.get(absDir)!;
        const env: Record<string, string> = existsSync(join(repo, "target")) ? { CARGO_TARGET_DIR: join(repo, "target") } : {};
        // JS projects: install dependencies from the new lockfile first (the fix step only touched the lockfile).
        if (existsSync(join(dir, "package.json"))) {
          const legacy = legacyPeers.has(absDir);
          const inst = installCommand(dir, legacy);
          const r = run(inst[0], inst.slice(1), dir, 15 * 60_000);
          if (!r.ok) {
            const entry: ApplyResult["verify"][number] = { dir: absDir, command: inst.join(" "), ok: false, output: r.output.slice(-3000) };
            entry.preexisting = failsOnBase(repo, wt.get(repo)!.base, relative(repo, absDir), inst, env, log, legacy) === true;
            res.verify.push(entry);
            log(`${entry.preexisting ? "≈" : "✗"} ${inst.join(" ")}${entry.preexisting ? " (fails the same way before the fix: an environment issue, not this change)" : ""}`);
            continue; // can't build without dependencies
          }
          res.verify.push({ dir: absDir, command: inst.join(" "), ok: true, output: "" });
        }
        const cmds = verifyCommands(dir);
        if (!cmds.length) log(`no build/test script found in ${relative(wt.get(repo)!.path, dir) || "."}: nothing to verify`);
        for (const cmd of cmds) {
          const r = run(cmd[0], cmd.slice(1), dir, 15 * 60_000, env);
          reap(dir);
          const entry: ApplyResult["verify"][number] = { dir: absDir, command: cmd.join(" "), ok: r.ok, output: r.output.slice(-3000) };
          if (!r.ok) {
            // Did it already fail before the upgrade? Run the same command on the base branch to find out.
            const onBase = failsOnBase(repo, wt.get(repo)!.base, relative(repo, absDir), cmd, env, log, legacyPeers.has(absDir));
            // Couldn't compare (base doesn't install) still blocks the PR: a build nobody could check isn't shipped.
            entry.preexisting = onBase === true;
            entry.baseBroken = onBase === "base-broken";
          }
          res.verify.push(entry);
          log(`${r.ok ? "✓" : entry.preexisting ? "≈" : "✗"} ${cmd.join(" ")}${entry.preexisting ? " (fails the same way on " + wt.get(repo)!.base + ": pre-existing, not caused by this fix)" : ""}`);
        }
      }
    }
    // A project can span several repos (VeilSuite = 8). Judge each repo on its own build/test, so one broken
    // repo keeps its branch for a human while the others still get their PRs.
    const failing = new Set(res.verify.filter((v) => !v.ok && !v.preexisting).map((v) => repoOf.get(v.dir)!));
    res.verifyFailedRepos = [...failing];
    const fixedIn = (repo: string) => {
      const comps = new Set(res.applied.filter((f) => repoOf.get(join(f.projectPath, dirname(f.component))) === repo).map((f) => f.component));
      return res.fixed.filter((f) => comps.has(f.slice(f.lastIndexOf(" (") + 2, -1)));
    };

    // 6. Commit on the fix branch (the worktree is deleted afterwards, so this is how the result survives).
    //    Only tracked files we changed: never `git add -A`.
    for (const [repo, { path, branch: b }] of wt) {
      const mine = fixedIn(repo);
      if (!mine.length || !git(path, ["status", "--porcelain", "--untracked-files=no"])) continue;
      gitOrThrow(path, ["add", "-u"]);
      const msg = `mycelium: upgrade ${mine.length} vulnerable package(s)${failing.has(repo) ? " [build failing]" : ""}\n\n${mine.map((f) => `- ${f}`).join("\n")}`;
      gitOrThrow(path, ["commit", "-q", "-m", msg]);
      committedRepos.push(repo);
      // Same change already sitting on an earlier, never-PR'd mycelium branch? Reuse that one instead of
      // piling up identical branches run after run.
      const twin = sameChangeBranch(repo, b, wt.get(repo)!.base);
      if (twin) {
        wt.get(repo)!.reused = twin;
        log(`same change as your existing branch ${twin}: reusing it instead of keeping ${b}`);
      } else log(`committed on ${b}`);
    }
    res.committed = committedRepos.length > 0;

    // 7. Optional PR into the branch you were on. Never merges; never PRs a failing build.
    const name = (repo: string) => relative(plan.projectPath, repo) || basename(repo);
    if (opts.pr) for (const repo of committedRepos.filter((r) => failing.has(r))) {
      log(`build/test failed in ${name(repo)}: branch ${wt.get(repo)!.reused ?? wt.get(repo)!.branch} kept for you to fix, but no PR opened`);
    }
    if (opts.pr) for (const repo of committedRepos) if (noPr.has(repo)) res.noPr.push(noPr.get(repo)!);
    if (opts.pr) {
      for (const repo of committedRepos.filter((r) => !noPr.has(r) && !failing.has(r))) {
        const w = wt.get(repo)!;
        try {
          res.prs.push(openPr(repo, w.reused ?? w.branch, w.target, plan, res, log, w.reused ? repo : w.path));
        } catch (e) {
          const why = errLine((e as Error).message);
          res.noPr.push(`${relative(plan.projectPath, repo) || basename(repo)}: ${why}`);
          log(`✗ PR not opened for ${repo}: ${why}`);
        }
      }
    }

    res.branch = [...new Set(committedRepos.map((r) => wt.get(r)!.reused ?? wt.get(r)!.branch))].join(", ") || null;
    if (!committedRepos.length) {
      res.branch = null;
      log("nothing changed: no branch left behind");
    }
  } finally {
    for (const [repo, { path, branch: b }] of wt) {
      reap(path);
      git(repo, ["worktree", "remove", "--force", path]);
      dropTemp(path);
      // Only after the worktree is gone can its branch be deleted (git refuses while it's checked out).
      if (!committedRepos.includes(repo) || wt.get(repo)!.reused) git(repo, ["branch", "-D", b]);
    }
  }
  return res;
}

/** pushFrom: the fix worktree. Pushing from there means pre-push hooks (e.g. "run the build") check the fixed code. */
function openPr(repo: string, branch: string, target: string, plan: FixPlan, res: ApplyResult, log: (s: string) => void, pushFrom = repo) {
  const remote = git(repo, ["remote", "get-url", "origin"]);
  if (!remote || !/github\.com[:/]/.test(remote)) throw new Error(`origin is not a GitHub remote (${remote ?? "none"})`);
  const base = target; // resolved in applyFixes: the same branch the fix was cut from
  const push = run("git", ["push", "-u", "origin", branch], pushFrom, 15 * 60_000);
  if (!push.ok) {
    const hook = /pre-push|hook/i.test(push.output);
    throw new Error(hook ? `your pre-push hook blocked the push:\n${push.output.slice(-1200)}` : `git push failed:\n${push.output.slice(-1200)}`);
  }
  log(`pushed ${branch}`);

  const dir = mkdtempSync(join(tmpdir(), "mycelium-pr-"));
  const bodyFile = join(dir, "body.md");
  writeFileSync(bodyFile, prBody(plan, res, repo));
  const inRepo = (fx: PlannedFix) => join(fx.projectPath, fx.component).startsWith(repo + "/");
  const fixedHere = res.applied.filter(inRepo);
  const title = prTitle(fixedHere, res.stillVulnerable);
  const r = run("gh", ["pr", "create", "--base", base, "--head", branch, "--title", title, "--body-file", bodyFile], repo, 120_000);
  if (!r.ok) throw new Error(r.output.trim());
  const url = r.output.trim().split("\n").filter((l) => l.startsWith("https://")).at(-1) ?? r.output.trim();
  log(`opened PR ${url} → ${base}`);
  return { repo, url, base };
}

/** PR description: what changed, which advisories it closes, what was left and why, and how it was verified. */
export function prBody(plan: FixPlan, res: Pick<ApplyResult, "applied" | "stillVulnerable" | "skipped" | "failed" | "verify">, repo?: string): string {
  const inRepo = (fx: PlannedFix) => !repo || join(fx.projectPath, fx.component).startsWith(repo + "/");
  const still = new Set(res.stillVulnerable.map((s) => s.split(" ")[0]));
  const fixed = res.applied.filter(inRepo).filter((fx) => !still.has(`${fx.name}@${fx.from}`));
  const link = (id: string) =>
    /^GHSA-/.test(id) ? `[${id}](https://github.com/advisories/${id})` : /^CVE-/.test(id) ? `[${id}](https://nvd.nist.gov/vuln/detail/${id})` : `[${id}](https://osv.dev/vulnerability/${id})`;
  const lines: string[] = [];
  lines.push(`Automated dependency security upgrade for **${plan.project}** by Mycelium 🍄.`, "");
  lines.push("### Fixed", "", "| Severity | Package | Upgrade | Lockfile | Advisories |", "|---|---|---|---|---|");
  for (const fx of fixed.sort((a, b) => severityRank(b.severity) - severityRank(a.severity))) {
    lines.push(`| ${fx.severity} | \`${fx.name}\` | ${fx.from} → ${fx.to}${fx.breaking ? " ⚠️ major" : ""} | \`${fx.component}\` | ${fx.vulns.slice(0, 4).map(link).join(" ")}${fx.vulns.length > 4 ? ` +${fx.vulns.length - 4}` : ""} |`);
  }
  lines.push("", "Each one was confirmed by re-reading the lockfile after the upgrade, not just by the install exiting cleanly.");
  if (res.stillVulnerable.length || res.skipped.length || res.failed.length) {
    lines.push("", "### Not fixed in this PR", "");
    for (const s of res.stillVulnerable) lines.push(`- \`${s}\`: the package manager kept the old version (a parent pins it)`);
    for (const s of res.skipped.filter((s) => inRepo(s.fix))) lines.push(`- \`${s.fix.name}\` ${s.fix.from}: ${s.reason}`);
    for (const f of res.failed.filter((f) => inRepo(f.fix))) lines.push(`- \`${f.fix.name}\` ${f.fix.from}: ${errLine(f.error)}`);
  }
  lines.push("", "### Verification", "");
  // Only this repo's checks: a multi-repo project (VeilSuite) used to list every repo's results in every PR.
  const checks = res.verify.filter((v) => !repo || v.dir === repo || v.dir.startsWith(repo + "/"));
  if (!checks.length) lines.push("Build/test was not run. Please run the app before merging.");
  else if (checks.every((v) => /^\S+ (ci|install)\b/.test(v.command))) lines.push("Dependencies install cleanly, but this project has no build or test script, so nothing ran the code. Please run the app before merging.", "");
  for (const v of checks) {
    lines.push(`- ${v.ok ? "✅" : v.preexisting ? "⚠️" : "❌"} \`${v.command}\`${v.baseBroken ? ": fails, but couldn't be compared: the base branch doesn't even install. Please check this one by hand" : v.preexisting ? ": fails identically on the base branch, so it's pre-existing and not caused by these upgrades" : ""}`);
  }
  lines.push("", "_Review the lockfile diff before merging. Mycelium never merges on its own._");
  return lines.join("\n");
}

/** Applies one lockfile's fixes. npm re-resolves once for the whole batch; other ecosystems go fix by fix. */
function applyComponent(dir: string, lock: string, fxs: PlannedFix[], log: (s: string) => void): {
  ok: PlannedFix[];
  failed: { fix: PlannedFix; error: string }[];
  human?: { fix: PlannedFix; reason: string; human: true }[];
  legacy?: boolean;
} {
  if (fxs[0].ecosystem === "npm") {
    try {
      return { ok: fxs, failed: [], legacy: applyNpm(dir, lock, fxs, log) };
    } catch (e) {
      const error = (e as Error).message.slice(0, 2000);
      return { ok: [], failed: fxs.map((fix) => ({ fix, error })) };
    }
  }
  const ok: PlannedFix[] = [];
  const failed: { fix: PlannedFix; error: string }[] = [];
  const human: { fix: PlannedFix; reason: string; human: true }[] = [];
  for (const fx of fxs) {
    try {
      applyOne(dir, lock, fx);
      ok.push(fx);
      log(`${fx.strategy}: ${fx.name} ${fx.from} → ${fx.to}`);
    } catch (e) {
      if (e instanceof NeedsHuman) {
        human.push({ fix: fx, reason: e.message, human: true });
        log(`· ${fx.name}: ${e.message}`);
      } else failed.push({ fix: fx, error: explain(fx, (e as Error).message).slice(0, 2000) });
    }
  }
  return { ok, failed, human };
}

/** Turn package-manager noise into the one sentence that matters. */
function explain(fx: PlannedFix, raw: string): string {
  const pin = raw.match(/required by package `([^`]+)`/);
  if (pin) return `${fx.name} is pinned by ${pin[1].replace(/ \(.*/, "")}: upgrade that crate instead.\n\n${raw}`;
  if (/is not installed/.test(raw)) return raw.split("\n")[0];
  return raw;
}

/** Is this exact version anywhere in a package-lock.json, top-level or nested? */
export function npmLockHas(text: string, name: string, version: string): boolean {
  try {
    return Object.entries<any>(JSON.parse(text).packages ?? {}).some(([k, v]) => k.endsWith(`node_modules/${name}`) && v?.version === version);
  } catch {
    return false;
  }
}

/** The override fixes npm accepted but didn't act on: the old version is still in the lockfile. */
export function ignoredOverrides(lockText: string, fxs: PlannedFix[]): PlannedFix[] {
  return fxs.filter((f) => f.strategy === "override" && npmLockHas(lockText, f.name, f.from));
}

export function prTitle(fixedHere: PlannedFix[], stillVulnerable: string[]): string {
  const still = new Set(stillVulnerable.map((s) => s.split(" ")[0]));
  const done = fixedHere.filter((f) => !still.has(`${f.name}@${f.from}`));
  const worst = [...done].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0];
  return `Mycelium: upgrade ${done.length} vulnerable package${done.length === 1 ? "" : "s"}` + (worst ? ` (${worst.severity.toLowerCase()}: ${worst.name})` : "");
}

let installedNpmMajor: string | undefined;
/** The command for a given npm major: the installed npm when it matches, otherwise that version through npx. */
function npmAt(major: string): string[] {
  installedNpmMajor ??= run("npm", ["--version"], tmpdir(), 30_000).output.trim().split(".")[0];
  return installedNpmMajor === major ? ["npm"] : ["npx", "--yes", `npm@${major}`];
}

/**
 * npm versions disagree about the same overrides. npm 11 applies some that npm 10 ignores, and each refuses the other's
 * lockfile in `npm ci` (lighthouse-sweep, ProjectPulse). So every lockfile is resolved with npm 10, whichever npm this
 * machine has, because npm 11 accepts that result; and it's checked against both before it's kept.
 */
const resolverNpm = () => npmAt("10");

/** Would `npm ci` accept this package.json + lockfile, on npm 10 and on npm 11? */
function npmCiProblem(dir: string, legacy: boolean): string | null {
  const args = ["ci", "--dry-run", "--ignore-scripts", "--no-audit", "--no-fund", ...(legacy ? ["--legacy-peer-deps"] : [])];
  for (const major of ["10", "11"]) {
    const [cmd, ...pre] = npmAt(major);
    const r = run(cmd, [...pre, ...args], dir, 5 * 60_000);
    // A failure to fetch that npm says nothing about the lockfile. Only npm's own verdict on the files counts.
    if (!r.ok && /EUSAGE|ERESOLVE/.test(r.output)) return `npm ${major}: ${r.output.match(/(?:Invalid|Missing): [^\n]+/)?.[0] ?? errLine(r.output)}`;
  }
  return null;
}

/** Same check on the untouched files, in a temp copy, to tell "we broke it" from "it was already like this". */
function npmCiProblemBefore(dir: string, pkg: string, lock: string, legacy: boolean): string | null {
  const tmp = mkdtempSync(join(tmpdir(), "mycelium-ci-"));
  try {
    writeFileSync(join(tmp, "package.json"), pkg);
    writeFileSync(join(tmp, "package-lock.json"), lock);
    const rc = safeRead(join(dir, ".npmrc"));
    if (rc) writeFileSync(join(tmp, ".npmrc"), rc);
    return npmCiProblem(tmp, legacy);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Resolve, then keep only what npm actually honored. An override that didn't move its package does nothing except
 * leave package.json disagreeing with the lockfile, which breaks `npm ci` on newer npm. Dropped fixes stay reported as
 * not fixed (step 4 re-reads the lockfile). Nothing leaves here unless `npm ci` would accept it.
 */
function applyNpm(dir: string, lock: string, fxs: PlannedFix[], log: (s: string) => void): boolean {
  const pkgPath = join(dir, "package.json");
  const lockPath = join(dir, lock);
  const original = { pkg: safeRead(pkgPath), lock: safeRead(lockPath) };
  const restore = () => {
    if (original.pkg !== null) writeFileSync(pkgPath, original.pkg);
    if (original.lock !== null) writeFileSync(lockPath, original.lock);
  };
  if (lock !== "package-lock.json") return resolveNpm(dir, lock, fxs, log);

  let active = fxs;
  let legacy = false;
  for (let attempt = 0; attempt < 4; attempt++) {
    legacy = resolveNpm(dir, lock, active, log);
    const ignored = ignoredOverrides(safeRead(lockPath) ?? "", active);
    if (!ignored.length) break;
    log(`npm ignored the override for ${ignored.map((f) => `${f.name}@${f.from}`).join(", ")}: taking it back out, so package.json matches the lockfile`);
    active = active.filter((f) => !ignored.includes(f));
    restore(); // from the top: moves made for a dropped override shouldn't stay in the tree
    if (!active.length) return false;
  }
  const problem = npmCiProblem(dir, legacy);
  if (problem) {
    if (original.pkg && original.lock && npmCiProblemBefore(dir, original.pkg, original.lock, legacy)) {
      log(`npm ci already refused this lockfile before the upgrade, and still does: ${problem}`);
      return legacy;
    }
    restore();
    throw new Error(`npm ci would refuse the upgraded lockfile, so it wasn't kept: ${problem}`);
  }
  return legacy;
}

/** Returns true when the lockfile had to be resolved with --legacy-peer-deps (the project already needed it). */
function resolveNpm(dir: string, lock: string, fxs: PlannedFix[], log: (s: string) => void): boolean {
  {
    const pkgPath = join(dir, "package.json");
    const original = { pkg: safeRead(pkgPath), lock: safeRead(join(dir, lock)) };
    // A resolve that fails must leave nothing behind: half-edited manifests and released lock entries would
    // otherwise be committed along with the fixes that did work.
    const fail = (message: string): never => {
      if (original.pkg !== null) writeFileSync(pkgPath, original.pkg);
      if (original.lock !== null) writeFileSync(join(dir, lock), original.lock);
      throw new Error(message);
    };
    const manifest = readJson(pkgPath);
    if (!manifest) throw new Error(`no package.json in ${dir}`);
    const manager = lock === "pnpm-lock.yaml" ? "pnpm" : lock === "yarn.lock" ? "yarn" : "npm";
    for (const fx of fxs) {
      if (fx.strategy === "bump-direct") {
        const field = ["dependencies", "devDependencies", "optionalDependencies"].find((k) => manifest[k]?.[fx.name])!;
        manifest[field][fx.name] = `^${fx.to}`;
      } else {
        const key = manager === "yarn" ? fx.name : `${fx.name}@^${major(fx.from)}`;
        const target =
          manager === "pnpm" ? ((manifest.pnpm ??= {}).overrides ??= {}) : manager === "yarn" ? (manifest.resolutions ??= {}) : (manifest.overrides ??= {});
        target[key] = `^${fx.to}`;
      }
    }
    const lockstep = alignLockstep(dir, lock, manifest, fxs, log);
    writeFileSync(pkgPath, JSON.stringify(manifest, null, detectIndent(pkgPath)) + "\n");
    log(`edited ${pkgPath}`);
    // npm keeps every locked node it can. Two ways that bites:
    //  - lockstep families: the new @angular/common lands next to the old locked @angular/forms, whose exact peer
    //    pins the old core → ERESOLVE. Unlock the family so it resolves as one set.
    //  - overrides: a nested copy (readdir-glob/node_modules/minimatch@5) stays locked and the override never applies.
    // Released packages are re-resolved within their declared ranges, so this only moves what the fix asks for.
    const release = [...lockstep, ...fxs.filter((f) => f.strategy === "override").map((f) => f.name)];
    if (manager === "npm" && release.length) unlockNpm(join(dir, lock), [...new Set(release)]);
    // Re-resolve the lockfile only: no node_modules, no install scripts, no native builds (sharp, better-sqlite3 …).
    // Dependencies get installed for real only if build/test verification runs.
    const args =
      manager === "npm" ? ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
      : manager === "pnpm" ? ["install", "--lockfile-only", "--ignore-scripts"]
      : yarnBerry(dir) ? ["install", "--mode=update-lockfile"]
      : ["install", "--ignore-scripts", "--non-interactive"];
    const [bin, ...pre] = manager === "npm" ? resolverNpm() : [manager];
    const resolve = (a: string[]) => run(bin, [...pre, ...a], dir);
    const first = resolve(args);
    if (first.ok && manager === "pnpm") {
      // pnpm can treat a lockfile as current while it still pins a version the override excludes (vite@7.3.0 under
      // vite@^7 → ^7.3.7), and neither `install` nor `update` moves it. Only a fresh resolve does. Verify then checks it.
      const lockPath = join(dir, lock);
      const stuck = fxs.filter((f) => f.strategy === "override" && pnpmLockHas(safeRead(lockPath) ?? "", f.name, f.from));
      if (stuck.length) {
        rmSync(lockPath, { force: true });
        const fresh = resolve(args);
        if (!fresh.ok) fail(`${manager} ${args.join(" ")} (fresh lockfile) failed:\n${fresh.output.slice(-1500)}`);
        log(`pnpm: regenerated ${lock} from scratch: the override didn't move ${stuck.map((f) => `${f.name}@${f.from}`).join(", ")}, so every package was re-resolved within its range`);
      }
    }
    if (first.ok) {
      // After released entries are re-added, npm's lock-only pass can leave their own dependencies out
      // (cityPassport: "Missing: jsonfile@6.2.1 from lock file", so `npm ci` refuses it). A second pass fills them in.
      if (manager === "npm" && release.length) {
        const again = resolve(args);
        if (!again.ok) fail(`${manager} ${args.join(" ")} (second pass) failed:\n${again.output.slice(-1500)}`);
      }
      log(`${manager}: lockfile updated in ${dir}`);
      return false;
    }
    // Peer conflict: was the project already living with one before we touched it (lockfile made with
    // --legacy-peer-deps)? Then resolve the same way it always has. If the conflict is new, it's ours: fail.
    if (manager === "npm" && /ERESOLVE/.test(first.output) && original.pkg && original.lock && strictResolveFails(dir, original.pkg, original.lock)) {
      const second = resolve([...args, "--legacy-peer-deps"]);
      if (second.ok) {
        log(`npm: lockfile updated with --legacy-peer-deps (the project's existing tree already has peer conflicts: ${errLine("x:\n" + first.output).slice(3)})`);
        return true;
      }
      fail(`${manager} ${args.join(" ")} --legacy-peer-deps failed:\n${second.output.slice(-1500)}`);
    }
    return fail(`${manager} ${args.join(" ")} failed:\n${first.output.slice(-1500)}`);
  }
}

/** Is this exact version an entry in a pnpm lockfile? */
export function pnpmLockHas(text: string, name: string, version: string): boolean {
  return new RegExp(`^  '?${escapeRe(name)}@${escapeRe(version)}['(:]`, "m").test(text);
}

/** Does the untouched package.json + lockfile already fail strict peer resolution? (Checked in a temp copy.) */
function strictResolveFails(dir: string, pkg: string, lock: string): boolean {
  const tmp = mkdtempSync(join(tmpdir(), "mycelium-peer-"));
  try {
    writeFileSync(join(tmp, "package.json"), pkg);
    writeFileSync(join(tmp, "package-lock.json"), lock);
    const rc = safeRead(join(dir, ".npmrc"));
    if (rc) writeFileSync(join(tmp, ".npmrc"), rc);
    const [bin, ...pre] = resolverNpm();
    const r = run(bin, [...pre, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], tmp);
    return !r.ok && /ERESOLVE/.test(r.output);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Scoped families released in lockstep (@angular/*, @nestjs/*, @babel/* …) peer-depend on each other's exact version,
 * so bumping some members and not the rest can't resolve (npm ERESOLVE). For every bumped direct dependency, move its
 * scope-mates that are locked at the same version to the same target, if that version exists for them.
 */
export function alignLockstep(dir: string, lock: string, manifest: any, fxs: PlannedFix[], log: (s: string) => void): string[] {
  const FIELDS = ["dependencies", "devDependencies", "optionalDependencies"];
  const locked = lockedVersions(dir, lock);
  const touched: string[] = []; // every package moved as part of a family (2+ members), so its lock entries can be released
  const families = new Map<string, { to: string; members: Set<string> }>();
  for (const fx of fxs) {
    if (fx.strategy !== "bump-direct" || !fx.name.startsWith("@") || !fx.to) continue;
    const key = `${fx.name.split("/")[0]}|${fx.from}`;
    const fam = families.get(key) ?? { to: fx.to, members: new Set<string>() };
    if (compareVersions(fx.to, fam.to) > 0) fam.to = fx.to;
    fam.members.add(fx.name);
    families.set(key, fam);
  }
  for (const [key, fam] of families) {
    const [scope, from] = key.split("|");
    const mates = FIELDS.flatMap((f) => Object.keys(manifest[f] ?? {}))
      .filter((n) => n.startsWith(scope + "/") && !fam.members.has(n) && locked.get(n) === from);
    const moved: string[] = [];
    for (const n of mates) {
      // Only if that exact release exists for this package; otherwise leave it and let npm say what's wrong.
      const has = run("npm", ["view", `${n}@${fam.to}`, "version"], dir, 60_000);
      if (!has.ok || !has.output.trim()) continue;
      moved.push(n);
    }
    const all = [...fam.members, ...moved];
    for (const n of all) {
      const field = FIELDS.find((f) => manifest[f]?.[n]);
      if (field) manifest[field][n] = `^${fam.to}`;
    }
    if (moved.length || fam.members.size > 1) touched.push(...all);
    if (moved.length) log(`kept ${scope}/* in lockstep at ^${fam.to}: also moved ${moved.join(", ")}`);
  }
  return touched;
}

/** Drop these packages' entries (top-level and nested) from a package-lock.json so npm re-resolves them together. */
export function unlockNpm(lockPath: string, names: string[]) {
  const text = safeRead(lockPath);
  if (!text) return;
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    return; // unreadable lockfile: let npm report it
  }
  const want = new Set(names);
  for (const key of Object.keys(json.packages ?? {})) {
    const m = key.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/);
    if (m && want.has(m[1])) delete json.packages[key];
  }
  for (const n of names) delete json.dependencies?.[n]; // lockfile v1/v2 legacy section
  const indent = text.match(/^\{\n([ \t]+)"/)?.[1] ?? 2;
  writeFileSync(lockPath, JSON.stringify(json, null, indent) + "\n");
}

/** Top-level installed versions from a lockfile (npm package-lock v2/v3, pnpm importers['.']). */
function lockedVersions(dir: string, lock: string): Map<string, string> {
  const out = new Map<string, string>();
  const text = safeRead(join(dir, lock));
  if (!text) return out;
  if (lock === "package-lock.json") {
    try {
      for (const [k, v] of Object.entries<any>(JSON.parse(text).packages ?? {})) {
        const m = k.match(/^node_modules\/((?:@[^/]+\/)?[^/]+)$/);
        if (m && v?.version) out.set(m[1], v.version);
      }
    } catch {
      /* unreadable lockfile: no alignment */
    }
  } else if (lock === "pnpm-lock.yaml") {
    const importers = text.split(/^importers:\s*$/m)[1]?.split(/^\S/m)[0] ?? "";
    const dot = importers.split(/^  \.:\s*$/m)[1]?.split(/^  \S/m)[0] ?? "";
    for (const m of dot.matchAll(/^      '?([^'\s:]+)'?:\n        specifier: [^\n]+\n        version: (\d[^(\s]*)/gm)) out.set(m[1], m[2]);
  }
  return out;
}

/** No automatic fix exists (yet): leave it for a human instead of reporting a failure on every run. */
export class NeedsHuman extends Error {}

/**
 * Registry crates in a Cargo.lock that depend on any of `pkgs` ("name@version"), as "name@version".
 * Path/workspace crates are left out: `cargo update` can't move them, they're your own code.
 */
export function cargoDependents(lockText: string, pkgs: string[]): string[] {
  const blocks = lockText.split(/^\[\[package\]\]$/m).slice(1).map((b) => ({
    name: b.match(/^name = "([^"]+)"/m)?.[1] ?? "",
    version: b.match(/^version = "([^"]+)"/m)?.[1] ?? "",
    registry: /^source = "registry\+/m.test(b),
    deps: [...(b.match(/^dependencies = \[([\s\S]*?)\]/m)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1].split(" ")),
  }));
  const versions = new Map<string, string[]>();
  for (const b of blocks) versions.set(b.name, [...(versions.get(b.name) ?? []), b.version]);
  const want = new Set(pkgs);
  const out = new Set<string>();
  for (const b of blocks) {
    if (!b.registry) continue;
    for (const [n, v] of b.deps) {
      // A bare name means only one version of it is in the lockfile.
      const ver = v ?? (versions.get(n)?.length === 1 ? versions.get(n)![0] : undefined);
      if (ver && want.has(`${n}@${ver}`)) out.add(`${b.name}@${b.version}`);
    }
  }
  return [...out];
}

function applyOne(dir: string, lock: string, fx: PlannedFix) {
  {
    switch (fx.strategy) {
      case "cargo-parent": {
        const lockPath = join(dir, "Cargo.lock");
        const before = safeRead(lockPath) ?? "";
        const present = () => new RegExp(`name = "${escapeRe(fx.name)}"\\nversion = "${escapeRe(fx.from)}"`).test(safeRead(lockPath) ?? "");
        if (!present()) break; // an earlier fix in this run already dropped it
        // Parent first, then grandparent (quick-xml ← plist ← tauri): the smallest move that drops the old version.
        let level = [`${fx.name}@${fx.from}`];
        const tried: string[] = [];
        for (let depth = 0; depth < 2 && present(); depth++) {
          level = cargoDependents(safeRead(lockPath) ?? "", level);
          if (!level.length) break;
          tried.push(...level);
          runOrThrow("cargo", ["update", ...level.flatMap((p) => ["-p", p])], dir);
        }
        if (present()) {
          writeFileSync(lockPath, before); // don't ship unrelated parent bumps that didn't fix anything
          throw new NeedsHuman(`no semver-compatible release of ${[...new Set(tried.map((p) => p.split("@")[0]))].join(", ") || "its parent"} drops ${fx.name} ${fx.from} yet: ` +
            `wait for an upstream release, or upgrade the parent by hand (\`mycelium why ${fx.name}@${fx.from}\`)`);
        }
        break;
      }
      case "cargo-update": {
        // A ladder, least invasive first. Success = the lockfile has a version ≥ the fix on the same major line.
        const lockText = () => safeRead(join(dir, "Cargo.lock")) ?? "";
        const reached = () =>
          [...lockText().matchAll(new RegExp(`name = "${escapeRe(fx.name)}"\\nversion = "([^"]+)"`, "g"))]
            .some((m) => major(m[1]) === major(fx.from) && compareVersions(m[1], fx.to!) >= 0);
        // 0. An earlier upgrade in this run may already have dropped it from the tree: that's a fix, not a failure.
        if (!new RegExp(`name = "${escapeRe(fx.name)}"\\nversion = "${escapeRe(fx.from)}"`).test(lockText())) break;
        // 1. Newest compatible release of just this crate.
        runOrThrow("cargo", ["update", "-p", `${fx.name}@${fx.from}`], dir);
        if (reached()) break;
        // 2. Crate families release in lockstep (tauri + tauri-runtime + tauri-utils …). Unlock them together
        //    so cargo can pick a matching set instead of a newer parent with stale siblings.
        const family = [...new Set([...lockText().matchAll(/^name = "([^"]+)"$/gm)].map((m) => m[1]))]
          .filter((n) => n === fx.name || n.startsWith(fx.name + "-") || n.startsWith(fx.name + "_"));
        if (family.length > 1) {
          runOrThrow("cargo", ["update", ...family.flatMap((n) => ["-p", n])], dir);
          if (reached()) break;
        }
        // 3. Last resort: exactly the fixed version. Can leave siblings mismatched, so verify will tell.
        runOrThrow("cargo", ["update", "-p", fx.name, "--precise", fx.to!], dir);
        break;
      }
      case "dotnet-add": {
        const proj = lock.endsWith("proj") ? lock : readdirSync(dir).find((f) => /\.(cs|fs|vb)proj$/.test(f))!;
        runOrThrow("dotnet", ["add", proj, "package", fx.name, "--version", fx.to!], dir);
        break;
      }
      case "pip-pin": {
        const file = join(dir, lock);
        const re = new RegExp(`^(${fx.name.replace(/[-_.]/g, "[-_.]")}(\\[[^\\]]*\\])?\\s*===?\\s*)${escapeRe(fx.from)}`, "im");
        const text = readFileSync(file, "utf8");
        if (!re.test(text)) throw new Error(`couldn't find ${fx.name}==${fx.from} in ${lock}`);
        writeFileSync(file, text.replace(re, `$1${fx.to}`));
        break;
      }
      case "uv-upgrade":
        runOrThrow("uv", ["lock", "--upgrade-package", `${fx.name}==${fx.to}`], dir);
        break;
      case "go-get":
        runOrThrow("go", ["get", `${fx.name}@v${fx.to}`], dir);
        runOrThrow("go", ["mod", "tidy"], dir);
        break;
      case "gradle-edit": {
        const file = join(dir, lock);
        const text = readFileSync(file, "utf8");
        writeFileSync(file, text.split(`${fx.name}:${fx.from}`).join(`${fx.name}:${fx.to}`));
        break;
      }
    }
  }
}

const yarnBerry = (dir: string) => (safeRead(join(dir, "yarn.lock")) ?? "").includes("__metadata:");

/** Clean install from the lockfile, per package manager. */
function installCommand(dir: string, legacyPeers = false): string[] {
  if (existsSync(join(dir, "pnpm-lock.yaml"))) return ["pnpm", "install", "--frozen-lockfile"];
  if (existsSync(join(dir, "yarn.lock"))) return yarnBerry(dir) ? ["yarn", "install", "--immutable"] : ["yarn", "install", "--frozen-lockfile"];
  return ["npm", "ci", "--no-audit", "--no-fund", ...(legacyPeers ? ["--legacy-peer-deps"] : [])];
}

/** Out-of-repo path dependencies (`path = "../../murmur/core"`, `"file:../lib"`), as paths relative to the repo root. */
export function outsidePaths(repo: string, workspaceSiblings?: Set<string>): string[] {
  const out = new Set<string>();
  const walk = (dir: string, depth: number) => {
    if (depth > 6) return;
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (!/^(node_modules|target|\.git|dist|build|\.next)$/.test(e.name)) walk(join(dir, e.name), depth + 1);
        continue;
      }
      if (e.name !== "Cargo.toml" && e.name !== "package.json" && e.name !== "pnpm-workspace.yaml") continue;
      const text = readFileSync(join(dir, e.name), "utf8");
      // pnpm workspaces can list sibling repos (TVS: `- '../VeilKey'`); a glob entry links the folder above the glob.
      const re = e.name === "Cargo.toml" ? /\bpath\s*=\s*"([^"]+)"/g
        : e.name === "pnpm-workspace.yaml" ? /^\s*-\s*['"]?(\.\.\/[^'"\s*{]*)/gm
        : /"(?:file|link|portal):([^"]+)"/g;
      for (const m of text.matchAll(re)) {
        const target = resolve(dir, m[1].replace(/\/+$/, ""));
        const rel = relative(repo, target);
        if (!rel.startsWith(".." + sep) || !existsSync(target)) continue;
        out.add(rel);
        if (e.name === "pnpm-workspace.yaml") workspaceSiblings?.add(rel);
      }
    }
  };
  walk(repo, 0);
  return [...out];
}

/**
 * A temp folder for a worktree of `repo`, laid out so sibling path dependencies still resolve:
 * the worktree sits deep enough that `../murmur/core` stays inside the temp folder, and the sibling sits next to it.
 * A pnpm workspace sibling that is its own git repo gets a real checkout (a detached worktree of its HEAD): pnpm
 * doesn't follow symlinks when it expands workspace entries, so a symlinked `../VeilKey` silently vanished from TVS's lockfile.
 * Anything else is a symlink to your real folder (read-only use: cargo/npm just need to read its manifests).
 */
const siblingCheckouts = new Map<string, { repo: string; path: string }[]>(); // temp root -> sibling worktrees to remove

function worktreeDir(repo: string, prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  let rels: string[] = [];
  const workspace = new Set<string>();
  try {
    rels = outsidePaths(repo, workspace);
  } catch {
    /* unreadable tree: just no links */
  }
  const ups = (rel: string) => rel.split(sep).findIndex((seg) => seg !== "..");
  const depth = Math.max(1, ...rels.map(ups));
  const path = join(root, ...Array(depth - 1).fill("up"), "repo");
  mkdirSync(dirname(path), { recursive: true });
  for (const rel of rels) {
    const n = ups(rel), top = rel.split(sep).slice(0, n + 1).join(sep); // "../../murmur"
    const link = resolve(path, top);
    if (existsSync(link)) continue;
    mkdirSync(dirname(link), { recursive: true });
    const src = resolve(repo, top);
    const srcRoot = git(src, ["rev-parse", "--show-toplevel"]);
    // Only pnpm workspace members need a real folder. `file:`/`link:`/Cargo path deps keep the symlink: they rely on
    // your built sibling (dist/), which a fresh checkout doesn't have.
    if (workspace.has(rel) && srcRoot && realpathSync(srcRoot) === realpathSync(src) && git(src, ["worktree", "add", "--detach", "-q", link, "HEAD"]) !== null) {
      siblingCheckouts.set(root, [...(siblingCheckouts.get(root) ?? []), { repo: src, path: link }]);
    } else symlinkSync(src, link);
  }
  return path;
}

/** Delete a worktree's temp folder, including any sibling checkouts made for it. */
function dropTemp(path: string) {
  const root = tempRoot(path);
  for (const s of siblingCheckouts.get(root) ?? []) git(s.repo, ["worktree", "remove", "--force", s.path]);
  siblingCheckouts.delete(root);
  rmSync(root, { recursive: true, force: true }); // symlinks to sibling folders are unlinked, not followed
}

/**
 * Stop anything still running out of a worktree. A test runner killed on timeout leaves its workers behind
 * (Jest workers sat orphaned for over an hour), still burning CPU and holding files in a folder we're about to delete.
 * Matched by the unique temp folder name, which shows up in both the /var and /private/var spelling of the path.
 */
export function reap(path: string) {
  if (process.platform === "win32") return;
  const id = basename(tempRoot(path));
  if (!/^mycelium-(wt|base)-\w+$/.test(id)) return; // never pattern-match anything broader than our own temp folder
  if (!run("pkill", ["-TERM", "-f", id], tmpdir(), 10_000).ok) return; // exit 1 = nothing was running
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2000); // let them exit cleanly
  run("pkill", ["-KILL", "-f", id], tmpdir(), 10_000);
}

function tempRoot(path: string): string {
  let p = path;
  while (dirname(p) !== p && !/^mycelium-(wt|base)-/.test(p.split(sep).pop()!)) p = dirname(p);
  return dirname(p) === p ? dirname(path) : p;
}

/** A different local mycelium/fix-* branch carrying exactly the same change (by patch-id) as `branch` on `base`. */
function sameChangeBranch(repo: string, branch: string, base: string): string | null {
  const id = (from: string, to: string) => {
    const diff = run("git", ["diff", from, to], repo, 60_000);
    if (!diff.ok || !diff.output.trim()) return null;
    try {
      return execFileSync("git", ["patch-id", "--stable"], { cwd: repo, input: diff.output, encoding: "utf8", maxBuffer: 256 << 20 }).split(" ")[0] || null;
    } catch {
      return null;
    }
  };
  const mine = id(base, branch);
  if (!mine) return null;
  const others = (git(repo, ["for-each-ref", "--format=%(refname:short)", "refs/heads/mycelium/fix-*"]) ?? "").split("\n").filter((b) => b && b !== branch);
  for (const o of others.reverse()) {
    const mb = git(repo, ["merge-base", base, o]);
    if (mb && id(mb, o) === mine) return o;
  }
  return null;
}

/**
 * One readable line from a multi-line command error: the headline plus the line that says why.
 * "npm install … failed:" alone tells you nothing; "… failed: Conflicting peer dependency: @angular/core@21.2.26" does.
 */
export function errLine(msg: string): string {
  const lines = msg.split("\n").map((l) => l.trim()).filter(Boolean);
  const head = (lines[0] ?? "").replace(/:$/, "");
  const rest = lines.slice(1).filter((l) => !/^npm (warn|WARN)\b/.test(l));
  const priority = [/Conflicting peer dependency/i, /ERR_PNPM_\w+/, /No matching version|ETARGET|E404|notarget/i, /Permission .* denied|returned error: \d+|rejected|denied/i,
    /^(fatal|error)[: ]/i, /npm error code \w+/i, /error/i];
  let why: string | undefined;
  for (const re of priority) if ((why = rest.find((l) => re.test(l)))) break;
  why ??= rest[0];
  return why ? `${head}: ${why.replace(/^npm error\s*/i, "").replace(/^remote:\s*/, "")}`.slice(0, 400) : head;
}

/** Runs `cmd` in a throwaway worktree of the base branch. true = it fails there too (pre-existing). */
/** true = fails there too (pre-existing). "base-broken" = the base branch can't even install, so there's nothing to compare. */
function failsOnBase(repo: string, base: string, relDir: string, cmd: string[], env: Record<string, string>, log: (s: string) => void, legacyPeers = false): boolean | "base-broken" {
  const path = worktreeDir(repo, "mycelium-base-");
  try {
    if (!git(repo, ["worktree", "add", "--detach", path, base])) return false;
    const dir = join(path, relDir);
    log(`checking whether \`${cmd.join(" ")}\` already fails on ${base}…`);
    if (existsSync(join(dir, "package.json"))) {
      const install = installCommand(dir, legacyPeers);
      const installed = run(install[0], install.slice(1), dir, 15 * 60_000).ok;
      // Checking the install itself: failing here too means it was already broken before the fix.
      if (install.join(" ") === cmd.join(" ")) return !installed;
      // The base can't install (its own lockfile is out of sync): the failure can't be pinned on the upgrade,
      // and it can't be cleared either. Say so plainly instead of "caused by this fix"; the caller still blocks the PR.
      if (!installed) {
        log(`≈ can't compare \`${cmd.join(" ")}\`: ${base} doesn't install either (\`${install.join(" ")}\` fails there)`);
        return "base-broken";
      }
    }
    return !run(cmd[0], cmd.slice(1), dir, 15 * 60_000, env).ok;
  } finally {
    reap(path);
    git(repo, ["worktree", "remove", "--force", path]);
    dropTemp(path);
  }
}

/** build + test scripts, if the project has them. */
function verifyCommands(dir: string): string[][] {
  const pkg = readJson(join(dir, "package.json"));
  if (pkg) {
    const manager = existsSync(join(dir, "pnpm-lock.yaml")) ? "pnpm" : existsSync(join(dir, "yarn.lock")) ? "yarn" : "npm";
    const out: string[][] = [];
    if (pkg.scripts?.build) out.push([manager, "run", "build"]);
    if (pkg.scripts?.test && !/no test specified/.test(pkg.scripts.test)) {
      // `ng test` (Karma) watches forever and opens a real Chrome window: one run, headless, then exit.
      const karma = /^\s*ng test\b/.test(pkg.scripts.test) && !/--watch/.test(pkg.scripts.test);
      out.push(karma ? [manager, "test", "--", "--watch=false", "--browsers=ChromeHeadless"] : [manager, "test"]);
    }
    return out;
  }
  if (existsSync(join(dir, "Cargo.toml"))) return [["cargo", "check"]];
  if (existsSync(join(dir, "go.mod"))) return [["go", "build", "./..."]];
  if (readdirSync(dir).some((f) => /\.(sln|csproj)$/.test(f))) return [["dotnet", "build"]];
  return [];
}

// ---------------------------------------------------------------- helpers

function run(cmd: string, args: string[], cwd: string, timeout = 10 * 60_000, env: Record<string, string> = {}): { ok: boolean; output: string } {
  try {
    const output = execFileSync(cmd, args, { cwd, timeout, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CI: "1", ...env } });
    return { ok: true, output };
  } catch (e: any) {
    if (e.code === "ENOENT") return { ok: false, output: `${cmd} is not installed` };
    return { ok: false, output: `${e.stdout ?? ""}${e.stderr ?? ""}` || e.message };
  }
}
function runOrThrow(cmd: string, args: string[], cwd: string) {
  const r = run(cmd, args, cwd);
  if (!r.ok) throw new Error(`${cmd} ${args.join(" ")} failed:\n${r.output.slice(-1500)}`);
}
function git(cwd: string, args: string[]): string | null {
  const r = run("git", args, cwd, 30_000);
  return r.ok ? r.output.trim() : null;
}
function gitOrThrow(cwd: string, args: string[]) {
  runOrThrow("git", args, cwd);
}
function readJson(p: string): any {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}
function safeRead(p: string) {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}
function detectIndent(p: string): string | number {
  const m = readFileSync(p, "utf8").match(/^\{\n([ \t]+)"/);
  return m ? m[1] : 2;
}
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
