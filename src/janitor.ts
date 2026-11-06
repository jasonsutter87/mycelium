// Finds code-janitor's @deprecate markers so Mycelium can flag ones already past their removal date. Detection only:
// the actual removal is code-janitor's job (the nightly cleanup shells out to its CLI). The format and the expiry
// rule mirror code-janitor/src/core (parser.ts, date-utils.ts): `@deprecate MM-DD-YYYY [reason: ...]`, and an
// undated `@deprecate` is removed on the next run, so it counts as expired here too.

const DEPRECATE_WITH_DATE = /@deprecate\s+(\d{2}-\d{2}-\d{4})(?:\s+reason:\s*(.+))?/i;
const DEPRECATE_NO_DATE = /@deprecate(?:\s*$|\s+[^0-9])/i;
const DATE = /(\d{2})-(\d{2})-(\d{4})/;

export interface Deprecation {
  line: number;
  date: string | null; // MM-DD-YYYY, or null when undated
  reason: string | null;
  expired: boolean;
}

/** MM-DD-YYYY → Date, exactly as code-janitor parses it. Returns null on a malformed date. */
function parseDeprecateDate(s: string): Date | null {
  const m = s.match(DATE);
  if (!m) return null;
  const [, mo, dy, yr] = m;
  const d = new Date(Number(yr), Number(mo) - 1, Number(dy));
  return isNaN(d.getTime()) ? null : d;
}

/** Every @deprecate marker in the text, with whether it's past its date (date < today). Undated markers are expired. */
export function scanDeprecations(text: string, now = new Date()): Deprecation[] {
  const today = new Date(now);
  today.setHours(0, 0, 0, 0);
  const out: Deprecation[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const dated = line.match(DEPRECATE_WITH_DATE);
    if (dated) {
      const d = parseDeprecateDate(dated[1]);
      out.push({ line: i + 1, date: dated[1], reason: (dated[2] ?? "").trim() || null, expired: !!d && d < today });
    } else if (DEPRECATE_NO_DATE.test(line)) {
      const reason = line.match(/reason:\s*(.+)/i);
      out.push({ line: i + 1, date: null, reason: reason ? reason[1].trim() : null, expired: true });
    }
  }
  return out;
}

/** Just the expired markers: what the per-PR check flags and the nightly cleanup removes. */
export const expiredDeprecations = (text: string, now = new Date()) => scanDeprecations(text, now).filter((d) => d.expired);
