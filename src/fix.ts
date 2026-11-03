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
      if (fx.direct && field) return { ...fx, strategy: "bump-direct", note: fx.note + `set ${field}.${fx.name} to ^${fx.to}` };
      const key = lock === "yarn.lock" ? fx.name : `${fx.name}@^${major(fx.from)}`;
      return { ...fx, strategy: "override", note: fx.note + `force ${key} → ^${fx.to} (transitive)` };
    }
    case "crates.io":
      // `cargo update --precise` can only move within ranges every dependent accepts, so a semver-major jump
      // needs a Cargo.toml edit (direct) or a newer parent crate (transitive). Don't promise what cargo can't do.
      if (fx.breaking) {
        return { ...fx, note: fx.note + (fx.direct
          ? `edit Cargo.toml: ${fx.name} = "${fx.to}" (major bump, check the changelog)`
          : `a parent crate pins ${fx.name} to ${major(fx.from)}.x: upgrade the parent (\`mycelium why ${fx.name}@${fx.from}\`)`) };
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
}

export interface ApplyResult {
  branch: string | null;
  repos: string[];
  applied: PlannedFix[];
  skipped: { fix: PlannedFix; reason: string }[];
  failed: { fix: PlannedFix; error: string }[];
  fixed: string[]; // "name@from" that no longer appear vulnerable after re-scan
  stillVulnerable: string[];
  /** preexisting: the same command also fails on the branch you started from, so the upgrade didn't cause it. */
  verify: { dir: string; command: string; ok: boolean; output: string; preexisting?: boolean }[];
  committed: boolean;
  prs: { repo: string; url: string; base: string }[];
  /** Repos that got a committed branch but can't get a PR (no GitHub remote, empty repo, push denied, duplicate branch). */
  noPr: string[];
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
  const res: ApplyResult = { branch: null, repos: [], applied: [], skipped: [], failed: [], fixed: [], stillVulnerable: [], verify: [], committed: false, prs: [], noPr: [], log: [] };
  const log = (s: string) => res.log.push(s);

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
    res.skipped.push({ fix: fx, reason: `${relative(fx.projectPath, dir) || dir} isn't in a git repo: fixes need git so they can be reviewed and undone` });
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
        if (git(repo, ["fetch", "-q", "origin", target]) === null || !git(repo, ["rev-parse", "--verify", "-q", `origin/${target}`])) {
          throw new Error(`couldn't fetch origin/${target} from GitHub`);
        }
        base = start = `origin/${target}`;
        if (target !== current) log(`PR mode: ${current} isn't on GitHub, so the PR goes into ${target} and is built on origin/${target}`);
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
        if (!present.has(`${relative(repo, join(fx.projectPath, fx.component))}|${fx.name}@${fx.from}`)) {
          res.skipped.push({ fix: fx, reason: `not present on ${wt.get(repo)!.base} upstream (already removed or upgraded there)` });
          todo.splice(i, 1);
        }
      }
    }
    if (!todo.length && wt.size) {
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
      const { ok, failed, legacy } = applyComponent(dir, component.split("/").pop()!, fxs, log);
      if (legacy) legacyPeers.add(join(plan.projectPath, dirname(component)));
      res.applied.push(...ok);
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
            entry.preexisting = failsOnBase(repo, wt.get(repo)!.base, relative(repo, absDir), inst, env, log, legacy);
            res.verify.push(entry);
            log(`${entry.preexisting ? "≈" : "✗"} ${inst.join(" ")}${entry.preexisting ? " (fails the same way before the fix: an environment issue, not this change)" : ""}`);
            continue; // can't build without dependencies
          }
        }
        const cmds = verifyCommands(dir);
        if (!cmds.length) log(`no build/test script found in ${relative(wt.get(repo)!.path, dir) || "."}: nothing to verify`);
        for (const cmd of cmds) {
          const r = run(cmd[0], cmd.slice(1), dir, 15 * 60_000, env);
          const entry: ApplyResult["verify"][number] = { dir: absDir, command: cmd.join(" "), ok: r.ok, output: r.output.slice(-3000) };
          if (!r.ok) {
            // Did it already fail before the upgrade? Run the same command on the base branch to find out.
            entry.preexisting = failsOnBase(repo, wt.get(repo)!.base, relative(repo, absDir), cmd, env, log, legacyPeers.has(absDir));
          }
          res.verify.push(entry);
          log(`${r.ok ? "✓" : entry.preexisting ? "≈" : "✗"} ${cmd.join(" ")}${entry.preexisting ? " (fails the same way on " + wt.get(repo)!.base + ": pre-existing, not caused by this fix)" : ""}`);
        }
      }
    }
    const verifyFailed = res.verify.some((v) => !v.ok && !v.preexisting);

    // 6. Commit on the fix branch (the worktree is deleted afterwards, so this is how the result survives).
    //    Only tracked files we changed: never `git add -A`.
    for (const [repo, { path, branch: b }] of wt) {
      if (!res.fixed.length || !git(path, ["status", "--porcelain", "--untracked-files=no"])) continue;
      gitOrThrow(path, ["add", "-u"]);
      const msg = `mycelium: upgrade ${res.fixed.length} vulnerable package(s)${verifyFailed ? " [build failing]" : ""}\n\n${res.fixed.map((f) => `- ${f}`).join("\n")}`;
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
    if (opts.pr && verifyFailed) log("build/test failed: branch kept for you to fix, but no PR opened");
    if (opts.pr) for (const repo of committedRepos) if (noPr.has(repo)) res.noPr.push(noPr.get(repo)!);
    if (opts.pr && !verifyFailed) {
      for (const repo of committedRepos.filter((r) => !noPr.has(r))) {
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
      git(repo, ["worktree", "remove", "--force", path]);
      rmSync(tempRoot(path), { recursive: true, force: true }); // symlinks to sibling folders are unlinked, not followed
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
  const worst = [...fixedHere].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0];
  const title = `Mycelium: upgrade ${fixedHere.length} vulnerable package${fixedHere.length === 1 ? "" : "s"}` +
    (worst ? ` (${worst.severity.toLowerCase()}: ${worst.name})` : "");
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
  if (!res.verify.length) lines.push("Build/test was not run. Please run the app before merging.");
  for (const v of res.verify) {
    lines.push(`- ${v.ok ? "✅" : v.preexisting ? "⚠️" : "❌"} \`${v.command}\`${v.preexisting ? ": fails identically on the base branch, so it's pre-existing and not caused by these upgrades" : ""}`);
  }
  lines.push("", "_Review the lockfile diff before merging. Mycelium never merges on its own._");
  return lines.join("\n");
}

/** Applies one lockfile's fixes. npm re-resolves once for the whole batch; other ecosystems go fix by fix. */
function applyComponent(dir: string, lock: string, fxs: PlannedFix[], log: (s: string) => void): {
  ok: PlannedFix[];
  failed: { fix: PlannedFix; error: string }[];
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
  for (const fx of fxs) {
    try {
      applyOne(dir, lock, fx);
      ok.push(fx);
      log(`${fx.strategy}: ${fx.name} ${fx.from} → ${fx.to}`);
    } catch (e) {
      failed.push({ fix: fx, error: explain(fx, (e as Error).message).slice(0, 2000) });
    }
  }
  return { ok, failed };
}

/** Turn package-manager noise into the one sentence that matters. */
function explain(fx: PlannedFix, raw: string): string {
  const pin = raw.match(/required by package `([^`]+)`/);
  if (pin) return `${fx.name} is pinned by ${pin[1].replace(/ \(.*/, "")}: upgrade that crate instead.\n\n${raw}`;
  if (/is not installed/.test(raw)) return raw.split("\n")[0];
  return raw;
}

/** Returns true when the lockfile had to be resolved with --legacy-peer-deps (the project already needed it). */
function applyNpm(dir: string, lock: string, fxs: PlannedFix[], log: (s: string) => void): boolean {
  {
    const pkgPath = join(dir, "package.json");
    const original = { pkg: safeRead(pkgPath), lock: safeRead(join(dir, lock)) };
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
    alignLockstep(dir, lock, manifest, fxs, log);
    writeFileSync(pkgPath, JSON.stringify(manifest, null, detectIndent(pkgPath)) + "\n");
    log(`edited ${pkgPath}`);
    // Re-resolve the lockfile only: no node_modules, no install scripts, no native builds (sharp, better-sqlite3 …).
    // Dependencies get installed for real only if build/test verification runs.
    const args =
      manager === "npm" ? ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
      : manager === "pnpm" ? ["install", "--lockfile-only", "--ignore-scripts"]
      : yarnBerry(dir) ? ["install", "--mode=update-lockfile"]
      : ["install", "--ignore-scripts", "--non-interactive"];
    const first = run(manager, args, dir);
    if (first.ok) {
      log(`${manager}: lockfile updated in ${dir}`);
      return false;
    }
    // Peer conflict: was the project already living with one before we touched it (lockfile made with
    // --legacy-peer-deps)? Then resolve the same way it always has. If the conflict is new, it's ours: fail.
    if (manager === "npm" && /ERESOLVE/.test(first.output) && original.pkg && original.lock && strictResolveFails(dir, original.pkg, original.lock)) {
      const second = run(manager, [...args, "--legacy-peer-deps"], dir);
      if (second.ok) {
        log(`npm: lockfile updated with --legacy-peer-deps (the project's existing tree already has peer conflicts: ${errLine("x:\n" + first.output).slice(3)})`);
        return true;
      }
      throw new Error(`${manager} ${args.join(" ")} --legacy-peer-deps failed:\n${second.output.slice(-1500)}`);
    }
    throw new Error(`${manager} ${args.join(" ")} failed:\n${first.output.slice(-1500)}`);
  }
}

/** Does the untouched package.json + lockfile already fail strict peer resolution? (Checked in a temp copy.) */
function strictResolveFails(dir: string, pkg: string, lock: string): boolean {
  const tmp = mkdtempSync(join(tmpdir(), "mycelium-peer-"));
  try {
    writeFileSync(join(tmp, "package.json"), pkg);
    writeFileSync(join(tmp, "package-lock.json"), lock);
    const rc = safeRead(join(dir, ".npmrc"));
    if (rc) writeFileSync(join(tmp, ".npmrc"), rc);
    const r = run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], tmp);
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
export function alignLockstep(dir: string, lock: string, manifest: any, fxs: PlannedFix[], log: (s: string) => void) {
  const FIELDS = ["dependencies", "devDependencies", "optionalDependencies"];
  const locked = lockedVersions(dir, lock);
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
    for (const n of [...fam.members, ...moved]) {
      const field = FIELDS.find((f) => manifest[f]?.[n]);
      if (field) manifest[field][n] = `^${fam.to}`;
    }
    if (moved.length) log(`kept ${scope}/* in lockstep at ^${fam.to}: also moved ${moved.join(", ")}`);
  }
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

function applyOne(dir: string, lock: string, fx: PlannedFix) {
  {
    switch (fx.strategy) {
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
function outsidePaths(repo: string): string[] {
  const out = new Set<string>();
  const walk = (dir: string, depth: number) => {
    if (depth > 6) return;
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (!/^(node_modules|target|\.git|dist|build|\.next)$/.test(e.name)) walk(join(dir, e.name), depth + 1);
        continue;
      }
      if (e.name !== "Cargo.toml" && e.name !== "package.json") continue;
      const text = readFileSync(join(dir, e.name), "utf8");
      const re = e.name === "Cargo.toml" ? /\bpath\s*=\s*"([^"]+)"/g : /"(?:file|link|portal):([^"]+)"/g;
      for (const m of text.matchAll(re)) {
        const rel = relative(repo, resolve(dir, m[1]));
        if (rel.startsWith(".." + sep) && existsSync(resolve(dir, m[1]))) out.add(rel);
      }
    }
  };
  walk(repo, 0);
  return [...out];
}

/**
 * A temp folder for a worktree of `repo`, laid out so sibling path dependencies still resolve:
 * the worktree sits deep enough that `../murmur/core` stays inside the temp folder, and a symlink there
 * points at your real sibling folder (read-only use: cargo/npm just need to read its manifests).
 */
function worktreeDir(repo: string, prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  let rels: string[] = [];
  try {
    rels = outsidePaths(repo);
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
    if (!existsSync(link)) {
      mkdirSync(dirname(link), { recursive: true });
      symlinkSync(resolve(repo, top), link);
    }
  }
  return path;
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
function failsOnBase(repo: string, base: string, relDir: string, cmd: string[], env: Record<string, string>, log: (s: string) => void, legacyPeers = false): boolean {
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
      if (!installed) return false; // can't compare a build without dependencies
    }
    return !run(cmd[0], cmd.slice(1), dir, 15 * 60_000, env).ok;
  } finally {
    git(repo, ["worktree", "remove", "--force", path]);
    rmSync(tempRoot(path), { recursive: true, force: true });
  }
}

/** build + test scripts, if the project has them. */
function verifyCommands(dir: string): string[][] {
  const pkg = readJson(join(dir, "package.json"));
  if (pkg) {
    const manager = existsSync(join(dir, "pnpm-lock.yaml")) ? "pnpm" : existsSync(join(dir, "yarn.lock")) ? "yarn" : "npm";
    const out: string[][] = [];
    if (pkg.scripts?.build) out.push([manager, "run", "build"]);
    if (pkg.scripts?.test && !/no test specified/.test(pkg.scripts.test)) out.push([manager, "test"]);
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
