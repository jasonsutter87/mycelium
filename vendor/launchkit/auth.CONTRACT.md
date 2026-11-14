# launchkit/auth-gatekeep: contract (v1.0, 2026-11-13)

The **client** half of gatekeep sign-in: OpenID Connect authorization-code flow with PKCE against a gatekeep
issuer (passkeys happen at the issuer; this kit never sees them). A drop-in for any app that has a server.
Written before the code. The tests (`test/auth-gatekeep*.test.js`, `test/auth-cli.test.js`) carry the IDs below:
every **B** behavior and every **T** threat has a test whose name starts with its ID.

- **What it gives an app:** `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/me` as one Web
  `(Request) => Response` handler, plus `auth(req) => { sub, email, name, role } | null` for the rest of the app.
- **Runtime:** plain ESM on Web Crypto: Node 20.12+, Netlify Functions, Bun, Cloudflare Workers, Next route handlers.
- **Dependencies:** none. Crypto is Web Crypto only (SHA-256, HMAC-SHA-256, Ed25519, ECDSA P-256, RSASSA-PKCS1-v1_5).
  Nothing hand-rolled: JWS verification is a thin parse around `crypto.subtle.verify`.
- **Shares with the billing kit:** the CLI, `src/crypto.js`, `src/store.js` and the store adapters, the framework
  shims (`toNodeHandler`, `toNextRoute`, `toNetlifyHandler`), the `--lk-*` UI theming.
- **Non-goals:** the passkey ceremony (gatekeep owns it); passwords or magic links (`src/auth.js` stays for apps
  without gatekeep); registering the client in gatekeep (printed, not automated: `clients.toml` is static);
  refresh tokens and `offline_access` (tokens are verified and discarded, never kept); resource-server mode (verifying a
  bearer token on an API); stateless sealed-cookie sessions (a store is required); per-user device limits
  (`src/sessions.js` can be layered on top through `onSignIn`, it is not built in); organisations and roles from
  claims (gatekeep issues none; roles come from your `allow`); Python.

## API

```js
import { createGatekeepAuth, allowlist, openSignup, ownersAndGuests, emailList, billingAuth, safeReturnTo } from './auth-gatekeep.js';

const gk = createGatekeepAuth({
  issuer,                 // 'https://id.gatekeepauth.com'. https, or http on a loopback host for development
  clientId,               // as registered in clients.toml: [A-Za-z][A-Za-z0-9_-]{0,63}
  secret,                 // 32+ chars. Signs the session cookie and the pre-auth cookie. Rotating it signs everyone out
  store,                  // launchkit store: get/set/del/list. Use prefixed(store, 'auth')
  allow,                  // REQUIRED policy: ({ email, emailVerified, sub, claims }) => boolean | { role } | Promise of those
  origin,                 // public origin, 'https://app.example.com'. Default: the request's own. Set it in production
  basePath = '/auth',
  scope = 'openid email',
  sessionTtlMs = 14 days, // absolute lifetime; there is no sliding renewal
  preAuthTtlMs = 10 min,
  clockSkewSec = 60,
  maxIdTokenAgeSec = 600, // reject an id_token whose iat is older than this at callback time
  algs = ['EdDSA', 'ES256', 'RS256'],   // narrowed further by the issuer's discovery doc when it lists algs
  recheckPolicy = true,   // run allow() again on every auth(req): removing an email takes effect at once
  rpLogout = true,        // RP-initiated logout at the issuer's end_session_endpoint when it has one
  postLogoutPath = `${basePath}/signed-out`,
  defaultReturnTo = '/',
  onSignIn,               // async ({ sub, email, name, role, claims }, req) => void. Throw to deny (e.g. create the account row)
  discoveryTtlMs = 1 h, jwksTtlMs = 1 h, fetchTimeoutMs = 5000,
  fetch, now,             // injectable, for tests
});

gk.handler(req)           // (Request) => Promise<Response>: the five routes below
gk.auth(req)              // => { sub, email, name, role } | null. Never throws for a bad or missing cookie
gk.requireUser(req)       // => user | Response (401 JSON for /api and Accept: application/json, else 303 to login?returnTo=). CSRF-guards unsafe methods
gk.guard(req)             // => null | Response(403). The CSRF guard alone
gk.csrfOk(req)            // => boolean
gk.loginUrl(returnTo?)    // '/auth/login?returnTo=...'
gk.revokeUser(sub)        // bump the user's session version: every session of theirs dies
gk.sweep()                // delete expired session and pre-auth records (call from a cron or occasionally)
gk.verifyIdToken(jwt, { nonce })  // => claims, or throws GatekeepError. Exposed for tests and tooling
gk.redirectUri            // the URI to register, e.g. 'https://app.example.com/auth/callback' (needs `origin` to be exact)

allowlist(['a@x.com', '@corp.com'])       // exact emails or @domain suffixes; verified email only
openSignup({ role = 'user' })             // any verified gatekeep account
ownersAndGuests({ owners, guests = true, guestRole = 'guest', ownerRole = 'owner' })   // quarry's case
emailList(process.env.ALLOWED_EMAILS)     // 'a@x.com, b@y.com' -> ['a@x.com', 'b@y.com']

// With the billing kit: billingRoutes(billing, { auth: billingAuth(gk.auth) })   // user -> { orgId: sub, email }
```

### HTTP routes (all under `basePath`, all `cache-control: no-store`)

| Route | Does |
| --- | --- |
| `GET /login?returnTo=` | Mints state, nonce, PKCE verifier; stores them server-side; sets the pre-auth cookie; 302 to the issuer's `authorization_endpoint`. |
| `GET /callback?code&state` | Checks the browser binding, exchanges the code, verifies the id_token, runs `allow`, creates the session, 303 to `returnTo`. Failure: an HTML page, no session, no cookie but a cleared pre-auth cookie. |
| `GET /logout` | A confirm page with a POST form. Changes nothing (a link in someone else's page cannot sign you out). |
| `POST /logout` | CSRF-guarded. Deletes the server-side session, clears the cookie, 303 to the issuer's `end_session_endpoint?post_logout_redirect_uri=` (or straight to `postLogoutPath` when there is none or `rpLogout` is false). |
| `GET /me` | `200 { user: { sub, email, name, role } }` or `200 { user: null }`. Never a token. |
| `GET /signed-out` | A static page that does not start a sign-in (landing on `/` after logout can start one at once and look like logout failed). |

### Cookies

| Cookie | Value | Attributes |
| --- | --- | --- |
| session: `__Host-lk_session` (https) or `lk_session` (http loopback) | `sid.exp.sig`: random 256-bit id, expiry, HMAC-SHA-256 | `HttpOnly; Secure (https); SameSite=Lax; Path=/; Max-Age`, no `Domain` |
| pre-auth: `__Host-lk_pre` (https) or `lk_pre` | `id.exp.sig`: random browser-binding id, expiry, HMAC | `HttpOnly; Secure (https); SameSite=Lax; Path=/; Max-Age=preAuthTtlMs` (`__Host-` so a sibling subdomain cannot plant it) |

`SameSite=Lax`, not `Strict`: the redirect back from the issuer is a cross-site navigation and must carry the pre-auth cookie.
Server records (store, under the caller's prefix): `session/<sha256 sid>` = `{ schema, sub, email, emailVerified, name, role, claims, iat, exp }`,
`ver/<sha256 sub>` = `{ schema, revokedBefore }` (a session is valid only if its `iat` is later; a missing record means nothing is revoked), `pre/<sha256 id>` = `{ state, nonce, verifier, returnTo, exp }`. HMAC purposes carry a version (`lk-auth-session/1`). Tokens are never written anywhere.

## Behaviors

Flow
- [ ] **B1** `/login` sends `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge` and `code_challenge_method=S256` to the discovered `authorization_endpoint`.
- [ ] **B2** state, nonce and verifier are 128, 128 and 256 bits of CSPRNG output, different on every login.
- [ ] **B3** The full flow works end to end: login, issuer, callback, session, `auth(req)`, `/me`, logout. The token request is a form POST with `grant_type`, `code`, `redirect_uri`, `client_id`, `code_verifier` and no secret.
- [ ] **B4** After a successful callback the user lands on the validated `returnTo` (default `/`).
- [ ] **B5** An `error` at the callback (`access_denied` ...) shows a fixed, friendly page with a retry link, status 400/403, and no session. Issuer text is never reflected.
- [ ] **B6** Pre-auth state is single use: the record is deleted when the callback reads it, so replaying the callback URL fails.

Discovery and keys
- [ ] **B7** Discovery is fetched once and cached for `discoveryTtlMs`; `issuer` in the document must equal the configured issuer exactly; endpoints must be https (or loopback http); if it lists `code_challenge_methods_supported` it must include S256.
- [ ] **B8** JWKS is cached for `jwksTtlMs`, and refetched when a token names an unknown `kid`. A refetch for a `kid` still unknown is not repeated for 30 s, and forced refetches are capped at 5 per minute overall, so bad tokens cannot make the app hammer the issuer.
- [ ] **B9** Accepted algorithms: `EdDSA` (Ed25519), `ES256` (P-256), `RS256` (RSA, 2048 bits or more), intersected with the issuer's advertised list. A JWK is only used for the algorithm its `kty`/`crv` fits, and honors its `alg` and `use` when present.
- [ ] **B10** Network calls to the issuer have a timeout, a body size cap (256 KiB) and `redirect: 'error'`.

id_token
- [ ] **B11** Verified: structure (3 parts, JSON header and payload), `alg` allow-list, signature, `iss` (exact), `aud` (string, or array containing `clientId`), `azp` (must equal `clientId` when present, and is required when `aud` has more than one entry), `exp` (with skew), `iat` (not in the future beyond skew, not older than `maxIdTokenAgeSec`), `nbf` when present, `nonce` (constant-time equal), non-empty string `sub`.
- [ ] **B12** Headers carrying `jku`, `jwk`, `x5u`, `x5c` or `crit` are rejected; `kid` is required.
- [ ] **B13** Clock skew is symmetric and bounded by `clockSkewSec`: an expired token inside the skew passes, outside fails; same for `iat` in the future.

Session
- [ ] **B14** The session cookie has the attributes in the table above; the cookie value never contains a claim, an email or a token.
- [ ] **B15** A new session id is minted on every login; a session cookie sent with the callback request is revoked (rotation).
- [ ] **B16** `auth(req)` accepts a cookie only if the signature verifies (constant time), it has not expired, the record exists, and `record.v` equals the user's current version.
- [ ] **B17** `POST /logout` deletes the record; the old cookie, replayed, no longer authenticates. `revokeUser(sub)` kills all of a user's sessions.
- [ ] **B18** With `recheckPolicy`, `allow()` runs on every `auth(req)`; a denial returns null and deletes the session; a role change applies at once.
- [ ] **B19** `/me` returns exactly `{ user }`; the user is exactly `{ sub, email, name, role }` (`name` falls back to the part of the email before `@`; `role` to `'user'`).

Sign-out
- [ ] **B20** Logout redirects to the discovered `end_session_endpoint` with `post_logout_redirect_uri` set to the app's own `postLogoutPath` (gatekeep accepts any URL on a registered redirect URI's origin). With `rpLogout: false`, or no `end_session_endpoint`, or discovery down, it signs out locally only.
- [ ] **B21** `GET /logout` never changes state.

Policy
- [ ] **B22** `allow` is required (a missing one throws at construction: fail closed). `false` denies: 403 page, no session, no cookie. `true` gives role `user`; `{ role }` sets it. `onSignIn` runs after `allow` and may deny by throwing.
- [ ] **B23** `allowlist` matches lower-cased emails, exact or `@domain`, and only when `emailVerified === true`. `openSignup` requires a verified email. `ownersAndGuests` gives owners `owner`, other verified accounts `guest` (or denies them with `guests: false`).
- [ ] **B24** `billingAuth(gk.auth)` turns the user into `{ orgId: sub, email }` for `billingRoutes`; a billing route with no session is 401, with one it runs.

Redirects and CSRF
- [ ] **B25** `returnTo` is accepted only as a same-origin path (an absolute URL on this app's own origin is reduced to its path); the value used is the parsed path, never the raw string; it falls back to `defaultReturnTo`; it never points back into `basePath`.
- [ ] **B26** `csrfOk`: GET/HEAD/OPTIONS pass. Unsafe methods pass when `Sec-Fetch-Site` is `same-origin`, or (no `Sec-Fetch-Site`) `Origin` equals the app origin. Anything else, including no headers at all, is refused. `guard` answers 403 JSON.
- [ ] **B27** Every response has `cache-control: no-store`; HTML pages carry a restrictive CSP, `x-content-type-options`, `referrer-policy: no-referrer`, `frame-ancestors 'none'`.

CLI (see README): `add auth` detects and writes the files; never overwrites; `update auth` re-vendors only; `doctor auth` checks env names, the 32-character secret, and the issuer only with `--online`; if billing is present its `auth` stub is wired.
- [ ] **B28** `add auth` works on the next, netlify, express and bun fixtures, and sign-in runs end to end against the fake issuer through each generated file.
- [ ] **B29** `add auth` never overwrites an existing file (writes `.new`), is idempotent, and appends to `.env.example` instead of clobbering it.
- [ ] **B30** `update auth` changes only `vendor/launchkit/`; `doctor auth` passes and fails correctly and never prints a value; `--online` is the only mode that touches the network.
- [ ] **B31** UI: `<lk-sign-in>`, `<lk-account>`, `<lk-signed-in>`, `<lk-signed-out>`, `useAuth()` read only `/auth/me` and sign out with a form POST; they never see a token.

## Threat model

Attacker capabilities: controls other sites the user visits, can send the user links, can run their own gatekeep
account and read their own authorization responses, can read and replay network captures of a victim's
past requests, can serve forged tokens from their own server, and can win a race now and then. Cannot break
TLS, SHA-256, HMAC, or the issuer's keys; cannot read the victim's HttpOnly cookies.

| ID | Threat | Defence | Test |
| --- | --- | --- | --- |
| **T1** | **Login CSRF**: attacker signs the victim into the attacker's account by sending the victim a callback URL with the attacker's `code` and `state` | `state` is bound to the browser by the signed HttpOnly pre-auth cookie. No cookie, or a cookie whose record has another state, ends in refusal | no cookie; the attacker's state with the victim's own cookie |
| **T2** | **Missing, forged, expired or tampered pre-auth cookie** | HMAC verify, expiry check, server-side record lookup; all fail closed | missing, bit-flipped, expired |
| **T3** | **Code injection / interception**: a stolen or injected `code` | PKCE S256 (the verifier lives only in the server-side record, never in a cookie or URL); the code is useless without it; the pre-auth record is single use | wrong verifier is refused by the issuer; replayed callback refused |
| **T4** | **Token leakage to JS or URLs** | Tokens are never stored, set in cookies, put in URLs, or returned: the id_token is verified and dropped; access and refresh tokens are ignored. Session cookie is HttpOnly. `/me` returns four fields. The code appears in a URL once, then the redirect is `no-referrer` | scan every response and the store for issued tokens; `/me` shape |
| **T5** | **Open redirect** via `returnTo` | Same-origin path only, parsed, not raw (`//evil`, `/\evil`, `https://evil`, `javascript:`, control characters, backslashes, `%0d%0a`) | 20 hostile values |
| **T6** | **Session fixation** | New session id on every login; any old session in the request is revoked; a cookie the attacker plants must carry our HMAC, so cannot be forged | planted forged cookie; old sid dead after login |
| **T7** | **Replay** of a captured session cookie after sign-out, of a callback URL, or of an old id_token | Server-side record deleted on logout (plus per-user version); pre-auth single use; id_token bound to the nonce and `iat` age | replayed cookie after logout; replayed callback; stale `iat` |
| **T8** | **JWKS rotation and `kid` confusion** | Refetch on unknown `kid` (bounded); `kid` required; key chosen by `kid` then checked against the algorithm's key type; negative cache against refetch floods; `jku`/`jwk`/`x5u` ignored by rejection | rotation works; bogus kid refetches once; kty mismatch |
| **T9** | **Algorithm confusion and `none`** | Allow-list `EdDSA`, `ES256`, `RS256`; `none`, `HS*`, and anything else fail before any key is read. Key import is typed per algorithm, so an HS256 token "signed" with the public key bytes cannot verify | alg `none`; HS256 with the public key; RS256 header on an Ed25519 key |
| **T10** | **Wrong issuer or audience** (a token minted for another client or another issuer) | `iss` exact, `aud` must contain `clientId`, `azp` rules | wrong aud, wrong iss, aud array without azp, azp other |
| **T11** | **Expired or not-yet-valid tokens, clock skew** | `exp`, `iat`, `nbf` checks with `clockSkewSec`; `now` injectable | expired; inside and outside skew; future iat |
| **T12** | **Mix-up** (a response from a different issuer, a poisoned discovery doc) | One configured issuer; the callback's `iss` parameter, when sent, must equal it, and is required when discovery advertises `authorization_response_iss_parameter_supported` (RFC 9207); the discovery `issuer` must equal it; endpoints must be https; the token endpoint is the discovered one | `iss=evil` at the callback; discovery with another issuer; http endpoint |
| **T13** | **Cookie scope and flags** | `HttpOnly`, `Secure`, `SameSite=Lax`, `Path`, no `Domain`; `__Host-` prefix on both cookies on https, so a sibling subdomain cannot set or shadow them (`__Secure-` would not stop that) | flag assertions on https and http |
| **T14** | **CSRF on cookie-authenticated unsafe requests** | `Sec-Fetch-Site`/`Origin` guard on `POST /logout` and on `requireUser`/`guard` for the app's own routes; `GET` never changes state | cross-site POST refused with the session intact |
| **T15** | **Revoked or demoted account still holds a session** | Server-side revocation (record and per-user version); policy re-checked per request | revoked session; removed from allowlist |
| **T16** | **Reflected content / injection into error pages** | Error pages use fixed text; nothing from the query string is echoed | `error_description=<script>` |
| **T17** | **Forged session cookie** | HMAC verify, constant-time compare; expiry inside the signed value | bit-flipped signature, edited expiry |
| **T18** | **SSRF-ish discovery and redirects** | Only the configured issuer is contacted; `redirect: 'error'`; timeouts; size caps | covered in B7/B10 tests |

Known limits, stated plainly:
- `auth(req)` called directly has no CSRF protection (`SameSite=Lax` does not stop same-site sibling POSTs): use `requireUser` or `guard` on unsafe routes.
- `/login` writes a store record per request and records have no store TTL: run `sweep()` periodically and rate-limit `/login` (`src/ratelimit.js`). `HEAD /login` writes nothing.
- Email is mutable at the issuer and allowlists match on email: a reassigned address inherits access. Key anything important on `sub`.
- Instances keep their own discovery and JWKS caches; a rotation reaches each on its first unknown `kid`. Secret rotation signs everyone out (no keyring yet).
- Without `origin`, a plain-http public request is refused (a TLS-terminating proxy must set `origin`); forwarded headers are never trusted.
- The store has last-write-wins writes. Two simultaneous callbacks for one pre-auth record could both read it before either deletes it;
  the issuer's single-use authorization code still stops the second exchange. A revoked session can live as long as one store round trip.
- Two login tabs share one pre-auth cookie; the second login supersedes the first, and the first tab's callback fails with a retry page.
- Host header trust: without `origin`, `redirect_uri` and the CSRF origin come from the request. The issuer exact-matches registered redirect URIs, which blunts
  this, but production apps should set `origin`.
- `email_verified` is trusted as the issuer states it. `sub` is the identity key; email is for display and allowlists.
- `Max-Age` is the only browser-side lifetime; a stolen cookie on a compromised device works until it expires, is revoked, or the secret rotates.

## Errors

`GatekeepError(message, code)`; codes: `config` (bad options), `discovery`, `jwks`, `token-exchange`, `invalid-token`, `denied`.
HTTP: login/callback failures are HTML pages with fixed text (the exception detail never reaches the browser). JSON routes answer
`{ error, message }` with a fixed message.

## Security

HMAC-SHA-256 (Web Crypto) signs cookies; sids are 256-bit CSPRNG; the store holds a SHA-256 of the sid, so a store leak
does not hand out sessions. The secret is the caller's (`AUTH_SECRET`, 32+ characters, `launchkit doctor auth` checks length).
No logging. No dependencies.

## Versioning

Semver. Breaking: a cookie name or format change (signs everyone out), a store key change, a route change, tightening the
allowed algorithms. Additive: options, helpers, algorithms. Gatekeep today issues only `EdDSA`; `ES256` and `RS256` are
accepted so an issuer or a self-hosted OIDC provider that uses them works, and are tested.
