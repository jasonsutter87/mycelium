// Which GitHub repos a server install watches, managed from the dashboard. The list file stays the source of truth, because
// `mycelium sync` and Rescan already read it. Removing a repo stops watching it through `ignored` and leaves the clone alone:
// a clone can hold a branch kept from a failed fix, and re-adding is instant.

import { execFile } from "node:child_process";
import { writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { DatabaseSync } from "node:sqlite";
import { cloneDirs } from "./sync.ts";

export interface GithubRepo {
  slug: string;
  owner: string;
  private: boolean;
  archived: boolean;
  fork: boolean;
  description: string;
  pushedAt: string | null;
}

export const validSlug = (s: unknown): s is string => typeof s === "string" && /^[\w][\w.-]*\/[\w.][\w.-]*$/.test(s);

// Only repos this account can push to: Mycelium couldn't open a fix PR on the rest.
const JQ = '.[] | select(.permissions.push) | {slug: .full_name, owner: .owner.login, private: .private, archived: .archived, fork: .fork, description: (.description // ""), pushedAt: .pushed_at}';

/** Every repo the signed-in GitHub account can push to. */
export async function listGithubRepos(): Promise<GithubRepo[]> {
  const { stdout } = await promisify(execFile)("gh", ["api", "--paginate", "user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=pushed", "--jq", JQ],
    { encoding: "utf8", timeout: 120_000, maxBuffer: 1 << 26 });
  return stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l) as GithubRepo);
}

export function writeRepoList(file: string, slugs: string[]) {
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, [...new Set(slugs)].sort((a, b) => a.localeCompare(b)).join("\n") + "\n");
  renameSync(tmp, file); // a crash mid-write can't leave half a list for the nightly sync
}

const getSetting = <T>(db: DatabaseSync, key: string, fallback: T): T => {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | undefined;
  return row ? JSON.parse(row.value) : fallback;
};
const setSetting = (db: DatabaseSync, key: string, value: unknown) =>
  db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT DO UPDATE SET value = excluded.value").run(key, JSON.stringify(value));

/** Applies a change to the list: returns the new list and the new `ignored` paths. Pure, so it can be tested without GitHub. */
export function planRepoChange(dir: string, list: string[], ignored: string[], add: string[], remove: string[]) {
  const next = [...new Set([...list.filter((s) => !remove.includes(s)), ...add])];
  const before = cloneDirs([...new Set([...list, ...add])]);
  const pathOf = (slug: string) => join(dir, before.get(slug) ?? slug.split("/")[1]);
  const unignore = new Set(add.map(pathOf));
  const nextIgnored = new Set(ignored.filter((p) => !unignore.has(p)));
  for (const s of remove) if (list.includes(s)) nextIgnored.add(pathOf(s));
  return { list: next, ignored: [...nextIgnored] };
}

export function applyRepoChange(db: DatabaseSync, dir: string, file: string, list: string[], add: string[], remove: string[]): string[] {
  const plan = planRepoChange(dir, list, getSetting<string[]>(db, "ignored", []), add, remove);
  setSetting(db, "ignored", plan.ignored);
  writeRepoList(file, plan.list);
  return plan.list;
}

// ---------------------------------------------------------------- watching new repos automatically

export interface AutoWatch {
  owners: string[]; // GitHub accounts whose new repos get added
  seen: string[]; // repos that existed the last time we looked: unticking one of these sticks
}
export const loadAutoWatch = (db: DatabaseSync) => getSetting<AutoWatch>(db, "repo_auto", { owners: [], seen: [] });

/** Repos that appeared since we last looked, under a watched owner. Archived ones can't take a fix PR, so they're skipped. */
export const newRepos = (available: GithubRepo[], auto: AutoWatch) =>
  available.filter((r) => auto.owners.includes(r.owner) && !auto.seen.includes(r.slug) && !r.archived).map((r) => r.slug);

export function saveAutoWatch(db: DatabaseSync, owners: string[], available: GithubRepo[]) {
  const auto = loadAutoWatch(db);
  // Everything visible now counts as seen: turning this on means new repos from here on, not every existing one.
  setSetting(db, "repo_auto", { owners: [...new Set(owners)], seen: [...new Set([...auto.seen, ...available.map((r) => r.slug)])] });
}

/** Adds any new repos to the list file. Called by `mycelium sync`, so both Rescan and the nightly run pick them up. */
export async function applyAutoWatch(db: DatabaseSync, dir: string, file: string, list: string[], fetch = listGithubRepos): Promise<string[]> {
  const auto = loadAutoWatch(db);
  if (!auto.owners.length) return [];
  const available = await fetch();
  const add = newRepos(available, auto);
  if (add.length) applyRepoChange(db, dir, file, list, add, []);
  saveAutoWatch(db, auto.owners, available);
  return add;
}
