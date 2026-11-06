// Finding API keys in what's being committed. Plain rules on purpose: instant, free, and the same answer every time.
// A key's value is never stored or shown, only its kind and where it is: a comment saying "this is the key" would
// publish it a second time.

export interface KeyHit { kind: string; file: string; line: number; commit: string | null }

export const KEY_PATTERNS: { kind: string; re: RegExp }[] = [
  { kind: "private key", re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/ },
  { kind: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { kind: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/ },
  { kind: "OpenAI API key", re: /\bsk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{40,}\b/ },
  { kind: "Stripe key", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/ },
  { kind: "Stripe test key", re: /\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b/ },
  { kind: "Stripe webhook secret", re: /\bwhsec_[A-Za-z0-9]{24,}\b/ },
  { kind: "Resend API key", re: /\bre_[A-Za-z0-9_]{20,}\b/ },
  { kind: "AWS access key", re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { kind: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { kind: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/ },
  { kind: "Discord webhook", re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]{20,}/ },
  { kind: "Google API key", re: /\bAIza[A-Za-z0-9_-]{35}\b/ },
  { kind: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { kind: "PyPI token", re: /\bpypi-[A-Za-z0-9_-]{50,}\b/ },
  { kind: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { kind: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { kind: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}\b/ },
  { kind: "DigitalOcean token", re: /\bdop_v1_[a-f0-9]{64}\b/ },
];

/** Blanks every known key format. For text about to leave this machine. */
export const redactKeys = (text: string): string =>
  KEY_PATTERNS.reduce((t, { kind, re }) => {
    const all = new RegExp(kind === "private key" ? /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY-----|$)/.source : re.source, "g");
    return t.replace(all, "[REDACTED]");
  }, text);

// Documentation values and placeholders. `mycelium:allow-key` on the line is the way out for a test fixture.
const PLACEHOLDER = /EXAMPLE|x{6,}|X{6,}|0{8,}|your[-_]?(?:api[-_]?)?key|placeholder|<[a-z_-]+>/i;
const ALLOW = "mycelium:allow-key";
const SECRET_FILE = /(^|\/)(\.env(\.[\w-]+)?|\.envrc|[\w.-]+\.env|id_(rsa|dsa|ecdsa|ed25519)|\.pypirc|\.netrc|\.git-credentials)$|\.(pem|p12|pfx|jks|keystore|tfvars|tfstate)$/;
const SAFE_FILE = /\.(example|sample|template|dist|defaults?)$/;

export const scanLine = (line: string): string | null => {
  if (line.includes(ALLOW)) return null;
  for (const { kind, re } of KEY_PATTERNS) {
    const m = re.exec(line);
    if (m && !PLACEHOLDER.test(m[0])) return kind;
  }
  return null;
};

/**
 * Reads a patch (`git log -p --format=commit:%H -U0`, or `git diff -U0`), looking only at added lines. Taking it commit by
 * commit matters: a key added and then deleted in the same PR is still in the history once that's merged.
 */
export function scanPatch(patch: string): KeyHit[] {
  const hits: KeyHit[] = [];
  const seen = new Set<string>();
  let commit: string | null = null, file = "", line = 0;
  const add = (hit: KeyHit) => {
    const key = `${hit.kind}|${hit.file}|${hit.line}`;
    if (!seen.has(key)) { seen.add(key); hits.push(hit); }
  };
  for (const raw of patch.split("\n")) {
    if (raw.startsWith("commit:")) { commit = raw.slice(7).trim(); continue; }
    if (raw.startsWith("diff --git ")) { file = ""; continue; }
    if (raw.startsWith("+++ ")) {
      file = raw === "+++ /dev/null" ? "" : raw.slice(4).replace(/^"?b\//, "").replace(/"$/, "");
      if (file && SECRET_FILE.test(file) && !SAFE_FILE.test(file)) add({ kind: "file that holds secrets", file, line: 0, commit });
      continue;
    }
    if (raw.startsWith("--- ")) continue;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) { line = Number(hunk[1]); continue; }
    if (raw.startsWith("+")) {
      const kind = file ? scanLine(raw.slice(1)) : null;
      if (kind) add({ kind, file, line, commit });
      line++;
    }
  }
  return hits;
}

/** Key shapes and file names only, so it's safe to print. */
export function describeHits(hits: KeyHit[]): string {
  return hits.map((h) => `${h.kind} in ${h.file}${h.line ? `:${h.line}` : ""}`).join("\n");
}

export const preCommitHook = (bin: string) => `#!/bin/sh
# Added by mycelium keys --install-hook. Stops known API key formats from being committed.
exec ${JSON.stringify(bin)} keys --staged
`;
