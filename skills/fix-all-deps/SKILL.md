---
name: fix-all-deps
description: Fix vulnerable dependencies across every project in ~/Documents/Companies with Mycelium, headless. Rescans everything, then for each project with safe upgrades it applies them in a throwaway worktree, runs build/test, and opens a GitHub PR. Never merges. Use when the user says "fix all dependencies", "fix all deps", "patch everything", or runs /fix-all-deps.
allowed-tools: Bash, Read
argument-hint: "[dry] [major] [project1,project2] [--min high]"
---

# /fix-all-deps: Mycelium across every project

Mycelium lives at `~/Documents/Companies/Mycelium` (CLI: `~/Documents/Companies/Mycelium/bin/mycelium`).
`fix --all` does the whole loop headless:
1. rescan the remembered folders
2. re-check OSV
3. sync PRs
4. for each project: plan → apply in a worktree → build/test → commit → push → PR

Projects run one at a time, and a failure in one doesn't stop the rest. Invoking this skill is the user's
go-ahead to push `mycelium/fix-*` branches and open PRs for safe upgrades. It never authorizes merging,
force-pushing, or touching the user's working folders.

## Arguments

Map the user's words to flags:

| User says | Flag |
|---|---|
| `dry`, "preview", "what would it do" | omit `--apply` (plan only, nothing pushed) |
| `major`, "include majors" | `--major` (major version bumps; mention they may need code changes) |
| project names | `--project a,b` |
| `--min high` / "only criticals" | `--min high` / `--min critical` |
| "no PRs", "just branches" | `--no-pr` |

Default (no args): `--apply` with build/test verification and PRs, safe upgrades only (no majors).

## Steps

1. **Run it.** It can take a while: installs and builds run per project, so use a long timeout or run it
   in the background.
   ```sh
   ~/Documents/Companies/Mycelium/bin/mycelium fix --all --apply [flags] 2>&1 | tail -150
   ```
   For `dry`, drop `--apply`.

2. **Read the JSON report.** Its path is on the last line (`report: ~/.mycelium/fix-all-<ts>.json`). Each
   row has a `status`:

   | Status | Meaning |
   |---|---|
   | `pr` | PR opened (`prs` has the URLs) |
   | `fixed` | committed on a branch, but no PR (`error` says why: not GitHub, push hook, etc.) |
   | `verify-failed` | the upgrade broke build/test; branch kept, no PR |
   | `failed` | the fix couldn't run (`error`) |
   | `manual-only` | only fixes that need a human (parent pins it, no fix published, prerelease-only, majors without `--major`) |
   | `planned` | dry run |
   | `nothing` | clean |

3. **Report to the user**, short and scannable:
   - **PRs opened:** one line each, `project → PR URL (N fixed)`
   - **Needs attention:** `verify-failed`, `failed` and `fixed`-without-PR rows, each with the one-line
     reason and the next step
   - **Manual only:** project names and counts, one line, no detail unless asked
   - totals: projects scanned, PRs opened, packages fixed

4. **Don't auto-fix failures.** If a project failed for an engine reason (a Mycelium bug, not the project's
   code), say so and offer to fix Mycelium itself. Don't hand-patch the project's repo, and never merge,
   close or force-push PRs on the user's behalf.

## Safety rails (built into the engine)

- Fixes run in a temp `git worktree`. The user's folders and uncommitted work are never touched.
- PRs are cut from GitHub's copy of the branch. Already-merged fixes and fixes in an open Mycelium PR
  are skipped, so re-running doesn't create duplicates.
- npm-family fixes rewrite lockfiles with install scripts disabled.
- Build/test failures that also happen on the base branch are marked pre-existing and don't block.
- Prerelease-only fixes (betas, RCs) and majors without `--major` are left for a human.
