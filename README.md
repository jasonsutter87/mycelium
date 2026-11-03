# 🍄 Mycelium

**Dependabot tells you a library is vulnerable. Mycelium tells you what it means for everything you run, and fixes it.**

You don't have one project. You have fifty: a Next.js site, a Tauri app, a .NET API, a Godot game, three
half-finished experiments. Each one pulls in hundreds of packages, which pull in hundreds more. Mycelium
crawls all of it like a fungus through soil: every project, every lockfile, every transitive dependency,
plus the infrastructure underneath (base images, CI actions, hosts, domains). It keeps that map in a local
database and watches it.

When a CVE lands anywhere in the graph, you find out **which projects are hit, how the package got there,
how exposed each project is, and what the fix is**. Then you click **Fix**, and you get a pull request.

```
$ mycelium scan ~/code
  ✓ 54 projects · 6,923 packages · 412 infra edges

$ mycelium check
  31 new advisories

$ mycelium report
CRITICAL next@16.1.1 npm  risk 99.7  GHSA-2464-fhr4-w9xw
         Next.js: Unauthenticated Remote Code Execution in Image Optimization API
         in: storefront, dashboard, launch-site, blog, admin
         storefront (public-web, package-lock.json)
           fix:  npm install next@^16.4.1
```

---

## Why

Per-repo alerting is solved. What isn't solved is the view across everything:

- **"A CVE just dropped for `axios`. Which of my projects ship it, and to whom?"** → `mycelium impact axios`
- **"Why is `nanoid@3` even in here?"** → `mycelium why nanoid` shows `app → postcss → nanoid`
- **"What should I fix first?"** Findings are ranked by severity × exposure × how many projects share them.
  A critical bug in a public website outranks the same bug in a local CLI tool.
- **"Can it just fix it?"** Yes. On a throwaway branch, verified by a rescan, built and tested,
  delivered as a PR. Your working folder is never touched.

Known CVEs are only one problem. Malicious packages, dependency confusion, license traps, abandoned
libraries, and misconfigured infrastructure are separate problems, and Mycelium checks for each of them.

---

## Quick start

Needs **Node ≥ 22.13**. It uses the built-in `node:sqlite` and native TypeScript type-stripping, so there's
no build step.

```sh
git clone https://github.com/jasonsutter87/mycelium && cd mycelium
npm install
ln -s "$PWD/bin/mycelium" ~/bin/mycelium      # anywhere on your PATH

mycelium scan ~/code       # map a folder of projects (remembered for next time)
mycelium check             # query OSV.dev for every package in the graph
mycelium serve             # open the live dashboard at http://mycelium.localhost:4747
```

Optional extras:

```sh
mycelium serve --install   # keep the dashboard running (macOS login item); --uninstall to stop
mycelium schedule          # daily scan + check with a macOS notification for anything new
```

---

## The dashboard

`mycelium serve` serves a local page with every project as a card:

- open CVEs and audit issues per project, ranked
- **🔧 Fix**: plan → choose what to apply (majors opt-in) → optionally **open a PR**
- PR tracking: findings show *"fix in PR #12"* or *"merged in #12, pull to apply"*
- **⬇ Pull**: fast-forwards your local branch after you merge, then rechecks. It only appears when that's safe.
- **↻ Rescan**: re-scans all folders, refreshes advisories, license/deprecation data, and PR status

It listens on `127.0.0.1` only, rejects unexpected `Host` headers (DNS rebinding), and requires a token
on every API call, so no other website can press the buttons.

---

## What it catches

`report` covers CVEs and `audit` covers everything else.

| Category | How | Source |
|---|---|---|
| **Known CVEs** | every package version vs. advisories, ranked by blast radius | OSV.dev |
| **Transitive dependencies** | full lockfile graph with `why` chains | lockfiles |
| **Malicious packages** | OpenSSF malicious-packages feed (`MAL-*`, always CRITICAL), plus packages that run install scripts | OSV.dev, lockfiles |
| **Dependency confusion** | `.npmrc` scoped registry resolved from public npm; pip `--extra-index-url`; git/HTTP installs; alternate registries; NuGet feeds without source mapping; missing integrity hashes | lockfiles, configs |
| **Licenses** | AGPL/SSPL in anything shipped, GPL in distributed apps, non-commercial (BUSL, PolyForm, CC-NC), unknown, all judged against your project's own license and how it ships | deps.dev |
| **Deprecated / outdated / abandoned** | deprecation flag + reason; direct deps 1 or 2+ majors behind; no release in 2+ years | deps.dev |
| **Infrastructure** | DB ports on all interfaces, privileged containers, `docker.sock` mounts, root containers, secrets in images/compose, `curl \| sh`, `pull_request_target` pwn requests, script injection in `run:`, `write-all` tokens, unpinned actions, committed `.env` files | Dockerfiles, compose, workflows, git |

### What it reads

| Ecosystem | Files | Transitive? |
|---|---|---|
| npm | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (classic + berry) | ✅ with edges |
| Rust | `Cargo.lock` | ✅ with edges |
| .NET | `packages.lock.json` · `*.csproj` + `Directory.Packages.props` | ✅ lockfile · direct only |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` | ✅ / direct |
| Go | `go.mod` | direct + `// indirect` |
| Android / JVM | `build.gradle(.kts)` + `gradle/libs.versions.toml` | direct only |

**Infrastructure:**
- **Containers and CI:** Dockerfiles, compose images, GitHub Actions `uses:`.
- **Hosts:** Vercel, Netlify, Fly, Cloudflare, Firebase, Render, Railway, Caddy, GitHub Pages.
- **Domains:** `CNAME`, Hugo `baseURL`, Astro `site`, `homepage`, Caddyfile.
- **Distribution:** Tauri, Expo, Capacitor, Android, Godot, browser extensions.

---

## Fixing

One engine with three entry points: the CLI (`fix`), the dashboard button (`serve`), and an AI agent (`mcp`).

```sh
mycelium fix storefront                          # dry run: show the plan
mycelium fix storefront --apply --verify         # apply on a branch, build + test
mycelium fix storefront --apply --verify --pr    # ...and open a GitHub PR
```

### How a fix runs

1. **Isolated.** It creates a throwaway `git worktree` on a new branch `mycelium/fix-<timestamp>`. With
   `--pr` that branch starts from `origin/<your branch>`, not your local copy, so unpushed work never
   leaks into the PR. Your folder, including uncommitted edits, is never touched.
2. **Applied.** It uses the smallest change that works for each ecosystem (table below). npm-family fixes
   rewrite only the lockfile with install scripts disabled, so native builds can't break the run.
3. **Verified by rescan.** "Fixed" means the re-parsed lockfile no longer contains the vulnerable version,
   not that a command exited 0.
4. **Built and tested** (`--verify`). It installs dependencies and runs the project's build and test
   scripts. If something fails, it runs the same step on the base branch: failures that happen there too
   are labeled *pre-existing* and don't block the PR.
5. **Committed and delivered.** The result is committed to the branch. With `--pr`, it pushes and opens a
   PR into the branch you were on. **It never merges and never force-pushes.**

| Ecosystem | Direct dependency | Transitive dependency |
|---|---|---|
| npm / pnpm / yarn | bump the range in `package.json` | `overrides` / `pnpm.overrides` / `resolutions`, scoped to the vulnerable major (`nanoid@^3`) |
| Cargo | `cargo update -p name@old` → unlock the crate family (`tauri`, `tauri-*`) → `--precise` | same; major jumps become "upgrade the parent" |
| .NET | `dotnet add package --version` | pin it top-level |
| Python | rewrite the `==` pin · `uv lock --upgrade-package` | |
| Go | `go get module@vX && go mod tidy` | |
| Gradle | rewrite the `"g:a:version"` literal | |

Major version bumps are skipped unless you pass `--major` (or tick the box). Anything that can't be
fixed safely is reported as manual, with the reason (for example *"pinned by tauri-plugin-updater"*).

### Everything at once

```sh
mycelium fix --all                 # refresh + dry plan for every project
mycelium fix --all --apply         # build/test + PR per repo, one project at a time
```

`--major`, `--min high`, `--project a,b`, `--no-pr` and `--no-verify` all work here. A failure in one project
doesn't stop the rest. A JSON report is written to `~/.mycelium/fix-all-<time>.json`. Re-running is safe:
already-merged fixes and fixes in an open PR are skipped. The `/fix-all-deps` Claude Code skill wraps this.

### After you merge

```sh
mycelium prs                 # sync mycelium/fix-* PRs and which findings each one fixes
mycelium pull storefront     # fast-forward only, on the base branch, with nothing unpushed
```

Mycelium never pulls on its own.

### As an agent (Claude Code / MCP)

```sh
claude mcp add mycelium -s user -- "$PWD/bin/mycelium" mcp
cp agents/mycelium-fixer.md ~/.claude/agents/
```

Then ask *"fix the critical vulns in storefront"*. The agent plans the fix and applies the safe
upgrades. For major bumps it reads the changelog and fixes the code that breaks. Everything happens on a
branch for you to review.

MCP tools: `mycelium_scan`, `mycelium_check`, `mycelium_projects`, `mycelium_findings`, `mycelium_impact`,
`mycelium_why`, `mycelium_audit`, `mycelium_fix_plan`, `mycelium_fix_apply`.

---

## Commands

| Command | What it does |
|---|---|
| `scan [folders…]` | Map projects: a folder of projects or a single one. Folders are remembered. |
| `check` | Query OSV.dev for every package; print what's new since last time. |
| `report` | Ranked findings with dependency paths and fix commands. `--top N` `--all` `--dev` `--html [file]` |
| `audit` | Everything that isn't a CVE. `--category X` `--project X` `--min high` `--all` `--offline` |
| `projects` | Every project: packages, open vulns, exposure, location. |
| `impact <pkg[@ver]>` | Which projects use this package? |
| `why <pkg[@ver]>` | How it got into each project (`a → b → c`). `--project name` |
| `infra` | Hosts, domains, images and actions. `--all` |
| `fix <project>` | Plan fixes (dry by default). `--apply` `--verify` `--pr` `--major` `--min high` `--only a,b` |
| `fix --all` | Every project, headless: refresh, then plan, or `--apply` (verify + PR each). |
| `prs` | Sync Mycelium's PRs from GitHub. |
| `pull <project>` | Fast-forward a project after its PR is merged. |
| `serve` | Live dashboard. `--port 4747` `--install` `--uninstall` |
| `watch [folders…]` | scan + check + macOS notification for new findings. |
| `schedule` | Daily launchd job running `watch`. `--hour 9` |
| `mcp` | MCP server over stdio. |

---

## Ranking

```
risk = severity × exposure × (1 + log2(projects affected))
```

- **severity:** the OSV/GHSA label, or computed from the CVSS 3.x vector. `MAL-*` is always critical.
- **exposure:** per project. `public-web` 3 · `distributed` / `self-hosted` 2 · `local` 1. It's inferred
  from hosting config, domains and how the project ships.
- Dev-only dependencies are hidden unless you pass `--dev`.

---

## Privacy

- Everything lives in `~/.mycelium/mycelium.db` (override with `MYCELIUM_DB`).
- Only package names and versions are sent to OSV.dev and deps.dev. No source code leaves your machine.
- `.env` files are flagged when committed to git, but their contents are never read.
- GitHub access goes through your own `gh` CLI login, only when you ask for PRs.

---

## Architecture

```
bin/mycelium          bash shim → node --experimental-strip-types src/cli.ts
src/
  cli.ts              commands
  scan.ts             project discovery, exposure, saving the graph
  parsers/            lockfiles (js, other), infra, config checks
  db.ts               node:sqlite schema + migrations
  osv.ts              OSV.dev batch queries, severity, version math
  depsdev.ts          licenses, deprecation, latest versions (deps.dev)
  graph.ts            findings, risk ranking, why-paths, impact
  audit.ts            non-CVE issues
  fix.ts              plan → worktree → apply → rescan → verify → commit → PR
  prs.ts              PR sync, which findings each PR fixes, safe pull
  serve.ts, report.ts dashboard server + HTML
  mcp.ts              MCP tools
agents/               Claude Code subagent definition
```

```sh
npm test            # node:test suite
npm run typecheck
```

## Known limits

- Exposure is per project, not per lockfile, so a monorepo with one public site marks every part public.
- Gradle, Go and csproj projects without lockfiles only show direct dependencies.
- No reachability analysis: it can't tell whether your code actually calls the vulnerable function.
- GitHub Actions and Docker images are flagged for pinning but not yet matched against advisories.
- PRs are GitHub-only (via `gh`). The dashboard's always-on mode and notifications are macOS-only.
