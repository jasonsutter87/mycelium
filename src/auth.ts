// Sign-in through Gatekeep, using launchkit's auth-gatekeep kit (vendor/launchkit, vendored unchanged; see
// vendor/launchkit/auth.CONTRACT.md). The kit does the OIDC code + PKCE flow, binds each login to the browser with a
// signed pre-auth cookie (that is what stops login CSRF), keeps sessions in a store and checks the allowlist on every request.
//
// Config: GATEKEEP_ISSUER, GATEKEEP_CLIENT_ID, ALLOWED_EMAILS (or ~/.mycelium/config.json "auth"), MYCELIUM_BASE_URL, and
// AUTH_SECRET (32+ characters; if unset, one is generated once and kept in the settings table, like the serve token).
// Register the app in Gatekeep with redirect URI <baseUrl>/auth/callback.
import { join } from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";
import { allowlist, createGatekeepAuth, type GatekeepUser } from "../vendor/launchkit/auth-gatekeep.js";
import { toNodeHandler } from "../vendor/launchkit/billing-http-adapters.js";
import { prefixed } from "../vendor/launchkit/store.js";
import { jsonFile } from "../vendor/launchkit/stores/json-file.js";

export interface AuthConfig { issuer: string; clientId: string; allowedEmails: string[] }
export type User = GatekeepUser;

export function createAuth(cfg: AuthConfig, baseUrl: string, dataDir: string, secret: string) {
  if (!cfg.issuer || !cfg.clientId) throw new Error("auth: issuer and clientId are required");
  if (!cfg.allowedEmails?.length) throw new Error("auth: list at least one email in allowedEmails");
  const origin = baseUrl.replace(/\/$/, "");
  const gk = createGatekeepAuth({
    issuer: cfg.issuer.replace(/\/$/, ""), clientId: cfg.clientId, secret, origin,
    store: prefixed(jsonFile(join(dataDir, "auth.json")), "auth"),
    allow: allowlist(cfg.allowedEmails),
    postLogoutPath: "/login",
  });
  // The kit speaks Web Request; the server speaks node:http.
  const web = (req: IncomingMessage) => new Request(origin + (req.url ?? "/"), { method: req.method, headers: req.headers as Record<string, string> });
  return {
    /** /auth/login, /callback, /logout, /me, /signed-out. */
    handle: toNodeHandler(gk.handler),
    /** The signed-in user, or null. */
    user: (req: IncomingMessage): Promise<User | null> => gk.auth(web(req)),
    /** CSRF guard for cookie-authenticated unsafe requests: false (and a 403 written) when the request is cross-site. */
    guard(req: IncomingMessage, res: ServerResponse): boolean {
      const refused = gk.guard(web(req));
      if (refused) res.writeHead(403, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify({ error: "cross-site request refused" }));
      return !refused;
    },
  };
}
