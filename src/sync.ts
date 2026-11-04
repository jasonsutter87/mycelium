// Headless servers have no working folders of yours, so they keep their own clones: `mycelium sync <dir>`.
// Fix runs happen in throwaway worktrees of these clones, so the clones themselves stay plain checkouts.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { reposIn } from "./dashboard.ts";

/** owner/name from any GitHub remote URL, or null. Tokens embedded in URLs are never returned. */
export function githubSlug(remote: string): string | null {
  const m = /github\.com[:/]+([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(remote.trim());
  return m ? `${m[1]}/${m[2]}` : null;
}

/** Folder name for a clone. The owner is included only when two repos would otherwise collide. */
export function cloneDirs(slugs: string[]): Map<string, string> {
  const names = slugs.map((s) => s.split("/")[1].toLowerCase());
  return new Map(slugs.map((s, i) => [s, names.filter((n) => n === names[i]).length > 1 ? s.replace("/", "__") : s.split("/")[1]]));
}

const git = (cwd: string, ...args: string[]) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 600_000 }).trim();

/** GitHub repos behind the projects this machine knows about, one owner/name per line. */
export function knownRepos(db: DatabaseSync): string[] {
  const out = new Set<string>();
  for (const { path } of db.prepare("SELECT path FROM projects").all() as { path: string }[]) {
    for (const repo of reposIn(path)) {
      try {
        const slug = githubSlug(git(repo, "remote", "get-url", "origin"));
        if (slug) out.add(slug);
      } catch { /* no remote: nothing to clone from */ }
    }
  }
  return [...out].sort();
}

/** Clone what's missing and fast-forward what's there. One failure doesn't stop the rest. Never force-updates. */
export function syncRepos(dir: string, slugs: string[], log: (s: string) => void): { cloned: string[]; updated: string[]; failed: string[] } {
  mkdirSync(dir, { recursive: true });
  const res = { cloned: [] as string[], updated: [] as string[], failed: [] as string[] };
  for (const [slug, folder] of cloneDirs(slugs)) {
    const path = join(dir, folder);
    try {
      if (!existsSync(join(path, ".git"))) {
        execFileSync("gh", ["repo", "clone", slug, path, "--", "--quiet"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 600_000 });
        res.cloned.push(slug);
        log(`cloned ${slug}`);
        continue;
      }
      const before = git(path, "rev-parse", "HEAD");
      git(path, "pull", "--ff-only", "--quiet");
      if (git(path, "rev-parse", "HEAD") !== before) {
        res.updated.push(slug);
        log(`updated ${slug}`);
      }
    } catch (e: any) {
      res.failed.push(slug);
      log(`✗ ${slug}: ${String(e.stderr || e.message).trim().split("\n")[0]}`);
    }
  }
  return res;
}

export const readRepoList = (file: string) =>
  readFileSync(file, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
