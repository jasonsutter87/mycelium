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

`mycelium serve` opens the dashboard. The flow is **sign in → overview → Check → Fix → PR**:

- **Overview**: every project with its findings by severity. Search, filter by status (needs attention, clean, accepted, PRs open) or exposure, and sort any column either way.
- **Check** is read-only: it re-reads the project's lockfiles and asks OSV. Nothing in your repo changes. **Fix stays locked until a check has run.**
- **Fix** shows the pipeline live: Pull → Branch → Fix → Test → Commit → Push → PR. It runs in a throwaway copy, safe upgrades start ticked and majors opt-in, and nothing merges on its own.
- **Pull** fast-forwards your folder after you merge, when that's safe.
- **Fixed** is the history of what Mycelium has fixed: every upgrade from its GitHub PRs, merged or awaiting merge, with the advisories it closed. It's read from the PR descriptions and kept permanently, so entries stay after you pull. Fixes on local-only branches (no GitHub PR) aren't listed.
- **Repos** (server installs): import from the GitHub account's repos or a pasted list, with live progress. Only the imported repos are fetched and scanned. Each repo has **Scan now**, repos that couldn't update appear under **Problems** with the reason, new repos from an account can be watched automatically, and accounts you don't care about can be hidden from the list. Unticking stops watching a repo and keeps its clone and fix history.
- **Profile** (your name, top right): company name, who can sign in, and the GitHub account Mycelium acts as.
- **Alerts**: email when a new critical appears or enough new highs are waiting (3 by default). One email per check. Turning alerts on treats what's already open as known, and a failed send is retried at the next check. Needs `RESEND_API_KEY` and `MYCELIUM_EMAIL_FROM`; on a server they go in `~/.config/mycelium/env`.
- **Findings, Audit, Infrastructure** tabs cover everything else, and **Rescan all** refreshes every project.

It listens on `127.0.0.1` only, rejects unexpected `Host` headers (DNS rebinding), and requires a token on every API call, so no other website can press the buttons.

### Sign-in (optional)

Sign-in uses [Gatekeep](https://gatekeepauth.com). Register an app with redirect URI `<baseUrl>/auth/callback`, then add `~/.mycelium/config.json`:

```json
{
  "baseUrl": "https://mycelium.example.com",
  "host": "0.0.0.0",
  "auth": { "issuer": "https://<gatekeep issuer>", "clientId": "mycelium", "allowedEmails": ["you@example.com"] }
}
```

Mycelium refuses to listen on anything but this computer unless sign-in is configured.

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

## PR reviews

On a server install, the **Reviews** page turns on an adversarial AI reviewer for every PR on your watched repos.

```
PR opened or updated → reviewer tries to break it → "Mycelium review" check + one comment on the PR
                                                     green: ready for a person to merge
                                                     red: sent back with notes (and an email to the alert list)
```

It runs through a logged-in Claude Code on the server, on that person's own plan, or through `ANTHROPIC_API_KEY` if that's set. The key is what to use anywhere you're offering Mycelium to other people, since a product can't run its customers on someone's Claude plan. Try it on one PR first, without posting anything:

```sh
mycelium review owner/name 123
```

- **Mycelium never merges.** To block merging on a failed review, make the `Mycelium review` check required in GitHub's branch rules.
- **It polls** every two minutes, so GitHub needs no way in to your server.
- **The reviewer can only read.** Its tools read git objects from that one commit, and Claude Code's own tools are switched off. It can't run code or write anywhere, and
  everything in a PR is treated as data. The verdict is computed from its findings, and a review that doesn't finish is never a pass.
- **Spending has a limit.** A daily cap (50 reviews by default) holds the rest in the queue, and the page shows the estimated cost.
  PRs from forks and dependency bots, and PRs already open when you turn this on or start watching a repo, are skipped until you ask or they change.
- **A file it can't read counts against the PR.** Files that may hold secrets aren't sent, so changing one sends the PR back for a person to check. Big lockfiles aren't sent either: the comment says so, and Fungi covers their vulnerabilities.

### Key watcher and Fungi

Two more agents on the same page, each with its own check. They use plain rules with no AI, so they're free and also cover PRs from
dependency bots and forks. They only read git objects and never run a PR's code.

- **Key watcher** (`Mycelium keys`) looks for known API key formats and secret files in every commit of a PR, so a key added and then deleted is still caught.
  It never shows the value. A key found here is already on GitHub, so replace it. To stop one before it's committed: `mycelium keys --install-hook`.
- **Fungi** (`Mycelium fungi`) checks packages a PR's lockfile changes add against OSV, and fails on high, critical or malicious. Vulnerabilities that were already there
  stay with Findings. With nightly fixes on, each `mycelium sync` also opens fix PRs for high and critical production findings, leaving out major upgrades.

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
- Only package names and versions are sent to OSV.dev and deps.dev.
- Source code stays on your machine unless you turn on PR reviews. Then PR titles, descriptions, diffs and the files the reviewer opens go to Anthropic. Files that may hold secrets (`.env`, private keys, credentials) are left out, and known token formats are blanked first.
- `.env` files are flagged when committed to git, but their contents are never read.
- GitHub access goes through your own `gh` CLI login.

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
  review.ts           adversarial PR review: agent, read-only tools, queue, GitHub status + comment
  agents.ts, keys.ts  key watcher and fungi: rule-based checks on every PR
  review-tools.ts     those read-only tools as an MCP server, when reviews run through Claude Code
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
- PRs are GitHub-only (via `gh`). The dashboard's always-on mode (`--install`) and desktop notifications are macOS-only; email alerts work everywhere.
