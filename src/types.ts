// Shared shapes passed between parsers, the scanner and the database.

/** OSV ecosystem names (https://ossf.github.io/osv-schema/#affectedpackage-field). */
export type Ecosystem =
  | "npm"
  | "crates.io"
  | "NuGet"
  | "PyPI"
  | "Go"
  | "Maven";

export type Scope = "prod" | "dev";

export interface Pkg {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** true when the project's own manifest names it (not pulled in transitively). */
  direct: boolean;
  scope: Scope;
  /** npm: runs a preinstall/install/postinstall script (code execution at install time). */
  installScript?: boolean;
}

export type IssueCategory = "malicious" | "source" | "license" | "deprecated" | "outdated" | "abandoned" | "infra";

/** A non-CVE problem found while reading a project's files. */
export interface ScanIssue {
  category: IssueCategory;
  severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW";
  title: string;
  detail?: string;
  source: string;
}

/** A parent -> child dependency edge, keyed by "name@version" within one ecosystem. */
export interface Edge {
  parent: string;
  child: string;
}

/** One lockfile / manifest inside a project. */
export interface Component {
  kind: string; // e.g. "npm:package-lock", "cargo:Cargo.lock"
  path: string; // relative to the project root
  ecosystem: Ecosystem;
  packages: Pkg[];
  edges: Edge[];
}

export type InfraKind =
  | "docker-image" // FROM / compose image
  | "gh-action" // uses: owner/repo@ref
  | "host" // where it runs: vercel, fly, cloudflare, github-pages, ...
  | "domain" // a public hostname
  | "repo" // git remote
  | "distribution"; // shipped artifact: android-apk, expo, tauri-desktop, ...

export interface Infra {
  kind: InfraKind;
  value: string;
  source: string; // file it came from, relative to project root
  /** Supply-chain smell, e.g. "unpinned tag", "uses :latest". */
  warning?: string;
}

export type Exposure = "public-web" | "distributed" | "self-hosted" | "local";

export const EXPOSURE_WEIGHT: Record<Exposure, number> = {
  "public-web": 3,
  distributed: 2,
  "self-hosted": 2,
  local: 1,
};

export const pkgKey = (name: string, version: string) => `${name}@${version}`;
