// One global SQLite file holds the graph for every project you own.
// Default: ~/.mycelium/mycelium.db   Override: MYCELIUM_DB=/path/to.db

import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DB_PATH =
  process.env.MYCELIUM_DB ?? join(homedir(), ".mycelium", "mycelium.db");

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  path       TEXT NOT NULL UNIQUE,
  exposure   TEXT NOT NULL,
  scanned_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS components (
  id         INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  path       TEXT NOT NULL,
  ecosystem  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS packages (
  id        INTEGER PRIMARY KEY,
  ecosystem TEXT NOT NULL,
  name      TEXT NOT NULL,
  version   TEXT NOT NULL,
  checked_at TEXT,
  UNIQUE (ecosystem, name, version)
);

-- Which packages each component pulls in.
CREATE TABLE IF NOT EXISTS uses (
  component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  package_id   INTEGER NOT NULL REFERENCES packages(id),
  direct       INTEGER NOT NULL,
  scope        TEXT NOT NULL,
  PRIMARY KEY (component_id, package_id)
);

-- Dependency edges, per component (the same package can have different parents in different lockfiles).
CREATE TABLE IF NOT EXISTS edges (
  component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  parent_id    INTEGER NOT NULL REFERENCES packages(id),
  child_id     INTEGER NOT NULL REFERENCES packages(id),
  PRIMARY KEY (component_id, parent_id, child_id)
);

CREATE TABLE IF NOT EXISTS infra (
  id         INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  value      TEXT NOT NULL,
  source     TEXT NOT NULL,
  warning    TEXT
);

CREATE TABLE IF NOT EXISTS vulns (
  id        TEXT PRIMARY KEY,
  summary   TEXT,
  severity  TEXT NOT NULL,        -- CRITICAL | HIGH | MODERATE | LOW | UNKNOWN
  aliases   TEXT NOT NULL,        -- JSON array (CVE ids live here)
  published TEXT,
  modified  TEXT NOT NULL,
  url       TEXT
);

CREATE TABLE IF NOT EXISTS package_vulns (
  package_id INTEGER NOT NULL REFERENCES packages(id),
  vuln_id    TEXT NOT NULL REFERENCES vulns(id),
  fixed      TEXT,                -- first fixed version, if OSV knows it
  first_seen TEXT NOT NULL,
  notified   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (package_id, vuln_id)
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Problems found while reading files: untrusted package sources, risky container/CI config, committed secrets.
CREATE TABLE IF NOT EXISTS scan_issues (
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  category   TEXT NOT NULL,      -- source | infra
  severity   TEXT NOT NULL,
  title      TEXT NOT NULL,
  detail     TEXT,
  source     TEXT NOT NULL       -- file, relative to project
);

-- Registry metadata per exact version (deps.dev): license, deprecation, publish date.
CREATE TABLE IF NOT EXISTS package_meta (
  package_id        INTEGER PRIMARY KEY REFERENCES packages(id),
  licenses          TEXT NOT NULL,  -- JSON array of SPDX expressions
  deprecated        INTEGER NOT NULL,
  deprecated_reason TEXT,
  published_at      TEXT,
  fetched_at        TEXT NOT NULL
);

-- Newest release per package name (deps.dev default version), for outdated/abandoned checks.
CREATE TABLE IF NOT EXISTS package_latest (
  ecosystem        TEXT NOT NULL,
  name             TEXT NOT NULL,
  latest           TEXT,
  latest_published TEXT,
  fetched_at       TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name)
);

-- PRs Mycelium opened (mycelium/fix-* branches), synced from GitHub.
CREATE TABLE IF NOT EXISTS prs (
  id         INTEGER PRIMARY KEY,
  repo       TEXT NOT NULL,       -- local repo root
  number     INTEGER NOT NULL,
  url        TEXT NOT NULL,
  state      TEXT NOT NULL,       -- OPEN | MERGED | CLOSED
  head       TEXT NOT NULL,
  base       TEXT NOT NULL,
  head_oid   TEXT,
  merge_oid  TEXT,
  synced_at  TEXT NOT NULL,
  UNIQUE (repo, number)
);

-- Which vulnerable package versions each PR removes (read from the PR's own lockfiles).
CREATE TABLE IF NOT EXISTS pr_fixes (
  pr_id        INTEGER NOT NULL REFERENCES prs(id) ON DELETE CASCADE,
  project_path TEXT NOT NULL,
  component    TEXT NOT NULL,     -- lockfile path relative to the project
  name         TEXT NOT NULL,
  version      TEXT NOT NULL
);

-- Every Mycelium PR, read from its own description. pr_fixes only knows what's still vulnerable in the current scan,
-- so it empties once a fix is pulled; this is the permanent record. Keyed by URL: worktrees of one repo share PRs.
CREATE TABLE IF NOT EXISTS pr_history (
  url       TEXT PRIMARY KEY,
  repo      TEXT NOT NULL,       -- owner/name on GitHub
  number    INTEGER NOT NULL,
  project   TEXT NOT NULL,
  state     TEXT NOT NULL,       -- OPEN | MERGED | CLOSED
  title     TEXT NOT NULL,
  opened_at TEXT,
  merged_at TEXT,
  fixes     TEXT NOT NULL,       -- JSON array of FixedEntry
  synced_at TEXT NOT NULL
);

-- Findings already emailed (or baselined when alerts were turned on). A text key, so it survives package rows being rebuilt.
CREATE TABLE IF NOT EXISTS alerted (
  key        TEXT PRIMARY KEY,     -- ecosystem|name@version|vuln id
  alerted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edges_child ON edges(child_id);
CREATE INDEX IF NOT EXISTS idx_uses_pkg ON uses(package_id);
`;

export function openDb(path = DB_PATH): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  // Columns added after v0.1. SQLite has no ADD COLUMN IF NOT EXISTS, so ignore "duplicate column".
  for (const sql of [
    "ALTER TABLE projects ADD COLUMN license TEXT",
    "ALTER TABLE packages ADD COLUMN install_script INTEGER NOT NULL DEFAULT 0",
  ]) {
    try {
      db.exec(sql);
    } catch {}
  }
  return db;
}

/** The company this install belongs to, shown in the top bar and alert subjects. "" when not set. */
export function companyName(db: DatabaseSync): string {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'company'").get() as { value: string } | undefined;
  return row?.value ?? "";
}

export function saveCompanyName(db: DatabaseSync, name: unknown): string {
  const clean = String(name ?? "").replace(/[\x00-\x1f\x7f]+/g, " ").trim();
  if (clean.length > 80) throw new Error("Keep the company name to 80 characters.");
  db.prepare("INSERT INTO settings (key, value) VALUES ('company', ?) ON CONFLICT DO UPDATE SET value = excluded.value").run(clean);
  return clean;
}

export function tx<T>(db: DatabaseSync, fn: () => T): T {
  db.exec("BEGIN");
  try {
    const out = fn();
    db.exec("COMMIT");
    return out;
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}
