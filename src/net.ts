// fetch() throws a bare "fetch failed" on any network blip (DNS stall, dropped connection), with the reason hidden in
// `cause`. Callers handle HTTP status codes; this handles the request never completing at all.

const describe = (e: any): string => e?.cause?.code ?? e?.cause?.message ?? (e?.name === "TimeoutError" ? "timed out" : e?.message ?? String(e));

/** The environment for anything that runs repo or dependency code: builds and install scripts have no business with these keys. */
export function withoutServiceKeys(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const { ANTHROPIC_API_KEY: _a, ANTHROPIC_AUTH_TOKEN: _b, CLAUDE_CODE_OAUTH_TOKEN: _c, RESEND_API_KEY: _d, ...rest } = env;
  return rest;
}

export async function fetchRetry(
  url: string,
  init: RequestInit = {},
  { tries = 4, timeoutMs = 60_000, baseMs = 1000 }: { tries?: number; timeoutMs?: number; baseMs?: number } = {},
): Promise<Response> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      if (attempt >= tries) throw new Error(`Couldn't reach ${new URL(url).host} after ${tries} tries (${describe(e)})`, { cause: e });
      await new Promise((r) => setTimeout(r, baseMs * 2 ** (attempt - 1)));
    }
  }
}
