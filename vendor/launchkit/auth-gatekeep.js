// launchkit/auth-gatekeep: the client half of gatekeep sign-in (OIDC authorization code + PKCE). Contract and threat
// model: docs/auth/CONTRACT.md. Web Crypto only, no dependencies; runs on Node 20.12+, Netlify, Bun, Workers.
//
//   const gk = createGatekeepAuth({ issuer, clientId, secret, store, allow: allowlist(['me@example.com']) });
//   gk.handler(req)   // /auth/login, /auth/callback, /auth/logout, /auth/me   (Request) => Response
//   gk.auth(req)      // { sub, email, name, role } | null

import { randomToken, sha256, sign, unsign, safeEqual, requireSecret } from './crypto.js';

export class GatekeepError extends Error {
  constructor(message, code = 'config') {
    super(message);
    this.name = 'GatekeepError';
    this.code = code;
  }
}

const DAY = 86_400_000;
const MAX_BODY = 256 * 1024;
const UNKNOWN_KID_COOLDOWN_MS = 30_000;
const ALL_ALGS = ['EdDSA', 'ES256', 'RS256'];
const ROUTES = { login: ['GET'], callback: ['GET'], logout: ['GET', 'POST'], me: ['GET'], 'signed-out': ['GET'] };
const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const SESSION_PURPOSE = 'lk-auth-session/1'; // the version is part of the HMAC input, so a format change can never validate an old cookie
const PRE_PURPOSE = 'lk-auth-pre/1';
const ID_RE = /^[A-Za-z0-9_-]{43}$/;

// ---- small helpers ------------------------------------------------------------------------------------------------

/** https, or http on a loopback host (development). Returns the URL, or throws. */
function checkEndpoint(value, what, code) {
  let u;
  try {
    u = new URL(String(value));
  } catch {
    throw new GatekeepError(`${what} is not a URL`, code);
  }
  const ok = u.protocol === 'https:' || (u.protocol === 'http:' && LOOPBACK.has(u.hostname));
  if (!ok || u.username || u.password) throw new GatekeepError(`${what} must be https (or http on localhost) with no credentials`, code);
  return u;
}

const b64uToBytes = (s) => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new GatekeepError('bad base64url', 'invalid-token');
  const p = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  return Uint8Array.from(atob(p), (c) => c.charCodeAt(0));
};
const b64uToJson = (s) => {
  try {
    const v = JSON.parse(new TextDecoder().decode(b64uToBytes(s)));
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  } catch {}
  throw new GatekeepError('malformed token', 'invalid-token');
};
const enc = new TextEncoder();
const b64uOfBytes = (bytes) => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const pkceChallenge = async (verifier) => b64uOfBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(verifier))));

/** All values of a cookie name (a sibling subdomain can add a second one; the caller tries each). */
function cookieValues(req, name) {
  const out = [];
  for (const part of (req.headers.get('cookie') ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) out.push(part.slice(i + 1).trim());
  }
  return out;
}

const cookieHeader = (name, value, { secure, path, maxAge }) => `${name}=${value}; Path=${path}; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', vary: 'Cookie', ...headers } });

// No form-action here on purpose: Chrome applies form-action to the redirect after a form POST, and sign-out redirects to the issuer.
const HTML_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
};
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
function page(status, title, message, actionsHtml = '', cookies = []) {
  const h = new Headers(HTML_HEADERS);
  for (const c of cookies) h.append('set-cookie', c);
  const css = 'font:16px/1.5 system-ui,sans-serif;max-width:26rem;margin:15vh auto;padding:0 1rem;color:#1b1e27}a,button{font:inherit;color:#2a47bd;background:none;border:0;padding:0;cursor:pointer;text-decoration:underline}h1{font-size:1.25rem';
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><style>body{${css}}</style><h1>${esc(title)}</h1><p>${esc(message)}</p>${actionsHtml}`, { status, headers: h });
}

/**
 * The only value `returnTo` may take: a same-origin path. Returns the PARSED path (never the raw input), or `fallback`.
 * Rejects protocol-relative URLs, backslashes, control characters, other origins, and anything inside `basePath`.
 */
export function safeReturnTo(raw, { origin, basePath = '/auth', fallback = '/' } = {}) {
  if (typeof raw !== 'string' || raw === '' || raw.length > 2048) return fallback;
  if (/[\u0000-\u001f\u007f\\]/.test(raw) || raw.startsWith('//')) return fallback;
  let u;
  let base;
  try {
    base = new URL(origin);
    u = new URL(raw, `${base.origin}/`);
  } catch {
    return fallback;
  }
  if (u.origin !== base.origin) return fallback;
  const path = u.pathname + u.search + u.hash;
  if (!path.startsWith('/') || path.startsWith('//')) return fallback;
  const bp = `/${String(basePath).replace(/^\/+|\/+$/g, '')}`;
  if (path === bp || path.startsWith(`${bp}/`) || path.startsWith(`${bp}?`)) return fallback;
  return path;
}

// ---- access policy helpers ----------------------------------------------------------------------------------------

/** 'a@x.com, b@y.com' (or an array) -> ['a@x.com', 'b@y.com'], lower-cased. */
export const emailList = (v) =>
  (Array.isArray(v) ? v : String(v ?? '').split(/[,\s]+/)).map((s) => String(s).trim().toLowerCase()).filter(Boolean);

const listOf = (v) => (typeof v === 'function' ? v() : v);
const matches = (email, entries) => entries.some((e) => (e.startsWith('@') ? email.endsWith(e) : email === e));

/** Exact emails or `@domain` suffixes. A list may be a function (read on every call) so edits apply at once. Verified email only. */
export const allowlist = (list) => ({ email, emailVerified }) => emailVerified === true && !!email && matches(String(email).toLowerCase(), emailList(listOf(list)));

/** Anyone with a verified gatekeep account. */
export const openSignup = ({ role = 'user' } = {}) => ({ sub, emailVerified }) => (emailVerified === true && !!sub ? { role } : false);

/** Owners (a list, like allowlist) get `owner`; every other verified account gets `guest`, or is denied with guests: false. */
export const ownersAndGuests = ({ owners, guests = true, guestRole = 'guest', ownerRole = 'owner' } = {}) => ({ email, emailVerified }) => {
  if (emailVerified !== true || !email) return false;
  if (matches(String(email).toLowerCase(), emailList(listOf(owners)))) return { role: ownerRole };
  return guests ? { role: guestRole } : false;
};

/** For billingRoutes({ auth }): the user as { orgId: sub, email }. One account = one billing org; map teams yourself. */
export const billingAuth = (auth) => async (req) => {
  const u = await auth(req);
  return u ? { orgId: u.sub, email: u.email } : null;
};

const normalizePolicy = (r) => {
  if (r === true) return { role: 'user' };
  if (r && typeof r === 'object') {
    const role = r.role ?? 'user';
    return typeof role === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(role) ? { role } : null;
  }
  return null;
};

// ---- the kit ------------------------------------------------------------------------------------------------------

export function createGatekeepAuth(opts = {}) {
  const {
    clientId, secret, store, allow, basePath: bp = '/auth', scope = 'openid email', sessionTtlMs = 14 * DAY, preAuthTtlMs = 600_000,
    clockSkewSec = 60, maxIdTokenAgeSec = 600, algs = ALL_ALGS, recheckPolicy = true, rpLogout = true, defaultReturnTo = '/', onSignIn,
    discoveryTtlMs = 3_600_000, jwksTtlMs = 3_600_000, fetchTimeoutMs = 5000,
  } = opts;
  const fetchImpl = opts.fetch ?? ((...a) => globalThis.fetch(...a));
  const now = opts.now ?? (() => Date.now());

  if (!opts.issuer) throw new GatekeepError('issuer is required');
  checkEndpoint(opts.issuer, 'issuer', 'config');
  const issuer = String(opts.issuer); // compared to iss byte for byte, exactly as configured
  const issuerBase = issuer.replace(/\/+$/, '');
  if (typeof clientId !== 'string' || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(clientId)) throw new GatekeepError('clientId must match [A-Za-z][A-Za-z0-9_-]{0,63}');
  requireSecret(secret, 'createGatekeepAuth');
  if (!store || typeof store.get !== 'function' || typeof store.set !== 'function' || typeof store.del !== 'function') throw new GatekeepError('store (get/set/del/list) is required');
  if (typeof allow !== 'function') throw new GatekeepError('allow(claims) is required. Use allowlist([...]), openSignup() or ownersAndGuests(...): the kit does not guess who may sign in');
  const algList = algs.filter((a) => ALL_ALGS.includes(a));
  if (!algList.length) throw new GatekeepError('algs must include EdDSA, ES256 or RS256');
  const basePath = `/${String(bp).replace(/^\/+|\/+$/g, '')}`;
  const postLogoutPath = opts.postLogoutPath ?? `${basePath}/signed-out`;
  const fixedOrigin = opts.origin ? checkEndpoint(opts.origin, 'origin', 'config').origin : null;
  const originOf = (req) => {
    if (fixedOrigin) return fixedOrigin;
    const o = new URL(req.url);
    if (o.protocol !== 'https:' && !LOOPBACK.has(o.hostname)) throw new GatekeepError('set the origin option: this request looks like plain http on a public host (a proxy that ends TLS?)', 'config');
    return o.origin;
  };
  const names = (secure) => ({ session: `${secure ? '__Host-' : ''}lk_session`, pre: `${secure ? '__Host-' : ''}lk_pre` });
  const sessionCookie = (secure, value, maxAge) => cookieHeader(names(secure).session, value, { secure, path: '/', maxAge });
  const preCookie = (secure, value, maxAge) => cookieHeader(names(secure).pre, value, { secure, path: '/', maxAge }); // __Host- needs Path=/: a sibling subdomain cannot plant it

  // ---- discovery and keys ---------------------------------------------------------------------------------------
  async function getJson(url, what, code) {
    let res;
    try {
      res = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(fetchTimeoutMs), headers: { accept: 'application/json' } });
    } catch {
      throw new GatekeepError(`${what} request failed`, code);
    }
    if (!res.ok) throw new GatekeepError(`${what} returned HTTP ${res.status}`, code);
    const text = await res.text();
    if (text.length > MAX_BODY) throw new GatekeepError(`${what} response too large`, code);
    try {
      return JSON.parse(text);
    } catch {
      throw new GatekeepError(`${what} is not JSON`, code);
    }
  }

  let disco = null; // { at, doc }
  let discoPromise = null;
  async function fetchDiscovery() {
    const d = await getJson(`${issuerBase}/.well-known/openid-configuration`, 'discovery', 'discovery');
    if (!d || typeof d !== 'object' || d.issuer !== issuer) throw new GatekeepError('discovery issuer does not match the configured issuer', 'discovery');
    for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) checkEndpoint(d[k], k, 'discovery');
    if (d.end_session_endpoint != null) {
      try {
        checkEndpoint(d.end_session_endpoint, 'end_session_endpoint', 'discovery');
      } catch {
        delete d.end_session_endpoint; // an unusable logout endpoint means local sign-out only
      }
    }
    if (Array.isArray(d.code_challenge_methods_supported) && !d.code_challenge_methods_supported.includes('S256')) throw new GatekeepError('the issuer does not support PKCE S256', 'discovery');
    return d;
  }
  async function discovery() {
    if (disco && now() - disco.at < discoveryTtlMs) return disco.doc;
    discoPromise ??= fetchDiscovery().then((doc) => (disco = { at: now(), doc }).doc).finally(() => { discoPromise = null; });
    try {
      return await discoPromise;
    } catch (e) {
      if (disco && now() - disco.at < discoveryTtlMs * 4) return disco.doc; // the issuer is down: keep serving a recent document
      throw e;
    }
  }
  const allowedAlgs = (d) => (Array.isArray(d.id_token_signing_alg_values_supported) ? algList.filter((a) => d.id_token_signing_alg_values_supported.includes(a)) : algList);

  let jwks = null; // { at, keys }
  let jwksPromise = null;
  const keyCache = new Map();
  const unknownKids = new Map();
  let refetches = []; // forced refetches in the last minute: at most 5, whatever the kids
  async function loadJwks(force) {
    if (!force && jwks && now() - jwks.at < jwksTtlMs) return jwks.keys;
    jwksPromise ??= (async () => {
      const d = await discovery();
      const body = await getJson(d.jwks_uri, 'jwks', 'jwks');
      if (!body || !Array.isArray(body.keys)) throw new GatekeepError('jwks has no keys', 'jwks');
      jwks = { at: now(), keys: body.keys.slice(0, 20).filter((k) => k && typeof k === 'object') };
      keyCache.clear();
      return jwks.keys;
    })().finally(() => {
      jwksPromise = null;
    });
    return jwksPromise;
  }

  const KEY_SPEC = {
    EdDSA: { kty: 'OKP', crv: 'Ed25519', import: { name: 'Ed25519' }, verify: { name: 'Ed25519' }, fields: ['kty', 'crv', 'x'] },
    ES256: { kty: 'EC', crv: 'P-256', import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' }, fields: ['kty', 'crv', 'x', 'y'] },
    RS256: { kty: 'RSA', import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' }, fields: ['kty', 'n', 'e'] },
  };
  const fits = (k, alg) => {
    const s = KEY_SPEC[alg];
    if (k.kty !== s.kty || (s.crv && k.crv !== s.crv)) return false;
    if (k.use != null && k.use !== 'sig') return false;
    if (k.alg != null && k.alg !== alg) return false;
    if (alg === 'RS256' && b64uToBytes(String(k.n ?? '')).length < 256) return false; // under 2048 bits
    return true;
  };
  async function keyFor(kid, alg) {
    const find = (keys) => keys.find((k) => k.kid === kid && fits(k, alg));
    let jwk = find(await loadJwks(false));
    if (!jwk) {
      const last = unknownKids.get(kid);
      refetches = refetches.filter((t) => now() - t < 60_000);
      if ((last === undefined || now() - last > UNKNOWN_KID_COOLDOWN_MS) && refetches.length < 5) {
        refetches.push(now());
        unknownKids.delete(kid);
        unknownKids.set(kid, now());
        if (unknownKids.size > 64) unknownKids.delete(unknownKids.keys().next().value);
        jwk = find(await loadJwks(true));
        if (jwk) unknownKids.delete(kid);
      }
    }
    if (!jwk) throw new GatekeepError('no usable signing key for this token', 'invalid-token');
    const id = `${kid}:${alg}`;
    if (!keyCache.has(id)) {
      const s = KEY_SPEC[alg];
      const pub = Object.fromEntries(s.fields.map((f) => [f, jwk[f]]));
      try {
        keyCache.set(id, await crypto.subtle.importKey('jwk', pub, s.import, false, ['verify']));
      } catch {
        throw new GatekeepError('the signing key is not valid', 'invalid-token');
      }
    }
    return keyCache.get(id);
  }

  // ---- id_token -------------------------------------------------------------------------------------------------
  async function verifyIdToken(token, { nonce } = {}) {
    const bad = (m) => new GatekeepError(m, 'invalid-token');
    const parts = typeof token === 'string' && token.length < 16384 ? token.split('.') : [];
    if (parts.length !== 3 || parts.some((p) => !p)) throw bad('malformed token');
    const header = b64uToJson(parts[0]);
    const claims = b64uToJson(parts[1]);
    const d = await discovery();
    if (typeof header.alg !== 'string' || !allowedAlgs(d).includes(header.alg)) throw bad('unsupported algorithm');
    for (const h of ['jku', 'jwk', 'x5u', 'x5c', 'crit']) if (h in header) throw bad(`unsupported header ${h}`);
    if (typeof header.kid !== 'string' || !header.kid || header.kid.length > 200) throw bad('missing kid');
    const key = await keyFor(header.kid, header.alg);
    const sig = b64uToBytes(parts[2]);
    if (header.alg === 'ES256' && sig.length !== 64) throw bad('bad signature');
    let ok = false;
    try {
      ok = await crypto.subtle.verify(KEY_SPEC[header.alg].verify, key, sig, enc.encode(`${parts[0]}.${parts[1]}`));
    } catch {}
    if (!ok) throw bad('bad signature');

    if (claims.iss !== issuer) throw bad('wrong issuer');
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(clientId)) throw bad('wrong audience');
    if (aud.length > 1 && claims.azp !== clientId) throw bad('missing or wrong azp');
    if (claims.azp != null && claims.azp !== clientId) throw bad('wrong azp');
    const t = now() / 1000;
    const num = (v) => typeof v === 'number' && Number.isFinite(v);
    if (!num(claims.exp) || claims.exp <= t - clockSkewSec) throw bad('token expired');
    if (!num(claims.iat) || claims.iat > t + clockSkewSec) throw bad('token issued in the future');
    if (claims.iat < t - maxIdTokenAgeSec) throw bad('token too old');
    if (claims.nbf != null && (!num(claims.nbf) || claims.nbf > t + clockSkewSec)) throw bad('token not yet valid');
    if (typeof claims.nonce !== 'string' || typeof nonce !== 'string' || !safeEqual(claims.nonce, nonce)) throw bad('nonce mismatch');
    if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255) throw bad('missing sub');
    return claims;
  }

  // ---- sessions -------------------------------------------------------------------------------------------------
  const sessionKey = async (sid) => `session/${await sha256(sid)}`;
  const versionKey = async (sub) => `ver/${await sha256(sub)}`;
  const revokedBefore = async (sub) => (await store.get(await versionKey(sub)))?.revokedBefore ?? 0; // missing record = nothing revoked
  const toUser = (rec, role) => ({ sub: rec.sub, email: rec.email, name: rec.name, role });
  const display = (claims, email) => (typeof claims.name === 'string' && claims.name.trim() && claims.name.length <= 100 ? claims.name.trim() : (email.split('@')[0] || email));

  const parseSigned = async (raw, purpose) => {
    const value = await unsign(secret, purpose, raw);
    if (!value) return null;
    const [id, exp, ...rest] = value.split('.');
    if (rest.length || !ID_RE.test(id ?? '') || !/^\d{1,12}$/.test(exp ?? '')) return null;
    return Number(exp) * 1000 > now() ? { id, exp: Number(exp) * 1000 } : null;
  };

  async function sessionFromRequest(req) {
    const secure = originOf(req).startsWith('https:');
    for (const raw of cookieValues(req, names(secure).session)) {
      const c = await parseSigned(raw, SESSION_PURPOSE);
      if (!c) continue;
      const rec = await store.get(await sessionKey(c.id));
      if (!rec || !(rec.exp > now())) continue;
      if (!(rec.iat > (await revokedBefore(rec.sub)))) continue;
      return { sid: c.id, rec };
    }
    return null;
  }

  async function auth(req) {
    try {
      const s = await sessionFromRequest(req);
      if (!s) return null;
      let role = s.rec.role ?? 'user';
      if (recheckPolicy) {
        const p = normalizePolicy(await allow({ email: s.rec.email, emailVerified: s.rec.emailVerified, sub: s.rec.sub, claims: s.rec.claims }));
        if (!p) {
          await store.del(await sessionKey(s.sid));
          return null;
        }
        role = p.role;
      }
      return toUser(s.rec, role);
    } catch {
      return null;
    }
  }

  // ---- CSRF -----------------------------------------------------------------------------------------------------
  function csrfOk(req) {
    if (SAFE.has(req.method.toUpperCase())) return true;
    const site = req.headers.get('sec-fetch-site');
    if (site) return site === 'same-origin';
    const o = req.headers.get('origin');
    return !!o && o !== 'null' && o === originOf(req);
  }
  const guard = (req) => (csrfOk(req) ? null : json({ error: 'forbidden', message: 'Cross-site request refused.' }, 403));

  const loginUrl = (returnTo) => `${basePath}/login${returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ''}`;

  async function requireUser(req) {
    const blocked = guard(req);
    if (blocked) return blocked;
    const user = await auth(req);
    if (user) return user;
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/') || /json/.test(req.headers.get('accept') ?? '')) return json({ error: 'unauthorized', message: 'Sign in first.' }, 401);
    return new Response(null, { status: 303, headers: { location: loginUrl(url.pathname + url.search), 'cache-control': 'no-store' } });
  }

  // ---- routes ---------------------------------------------------------------------------------------------------
  const retry = `<p><a href="${basePath}/login">Try again</a></p>`;
  const unavailable = (cookies) => page(503, 'Sign-in unavailable', 'We could not reach the sign-in service. Try again in a moment.', retry, cookies);

  async function login(req, url) {
    const origin = originOf(req);
    const secure = origin.startsWith('https:');
    let d;
    try {
      d = await discovery();
    } catch {
      return unavailable();
    }
    const state = randomToken(16);
    const nonce = randomToken(16);
    const verifier = randomToken(32);
    const returnTo = safeReturnTo(url.searchParams.get('returnTo') ?? url.searchParams.get('next'), { origin, basePath, fallback: safeReturnTo(defaultReturnTo, { origin, basePath }) });
    const id = randomToken(32);
    const exp = now() + preAuthTtlMs;
    await store.set(`pre/${await sha256(id)}`, { state, nonce, verifier, returnTo, exp });
    const to = new URL(d.authorization_endpoint);
    for (const [k, v] of Object.entries({
      response_type: 'code', client_id: clientId, redirect_uri: `${origin}${basePath}/callback`, scope, state, nonce,
      code_challenge: await pkceChallenge(verifier), code_challenge_method: 'S256',
    })) to.searchParams.set(k, v);
    const h = new Headers({ location: to.toString(), 'cache-control': 'no-store' });
    h.append('set-cookie', preCookie(secure, await sign(secret, PRE_PURPOSE, `${id}.${Math.floor(exp / 1000)}`), Math.floor(preAuthTtlMs / 1000)));
    return new Response(null, { status: 302, headers: h });
  }

  /** Read and consume the pre-auth record this browser holds. Null when there is no valid one. */
  async function takePre(req, secure) {
    for (const raw of cookieValues(req, names(secure).pre)) {
      const c = await parseSigned(raw, PRE_PURPOSE);
      if (!c) continue;
      const key = `pre/${await sha256(c.id)}`;
      const rec = await store.get(key);
      if (!rec) continue;
      await store.del(key); // single use
      if (rec.exp > now()) return rec;
    }
    return null;
  }

  async function callback(req, url) {
    const origin = originOf(req);
    const secure = origin.startsWith('https:');
    const clear = [preCookie(secure, '', 0)];
    const q = url.searchParams;
    const pre = await takePre(req, secure);
    if (!pre) return page(400, 'Sign-in expired', 'That sign-in link is no longer valid. Start again.', retry, clear);
    const state = q.get('state');
    if (!state || !safeEqual(state, pre.state)) return page(400, 'Sign-in failed', 'That sign-in did not start in this browser. Start again.', retry, clear);
    const disc = await discovery().catch(() => null);
    const mustIss = disc?.authorization_response_iss_parameter_supported === true; // RFC 9207 2.4
    if ((q.has('iss') && q.get('iss') !== issuer) || (mustIss && !q.has('iss'))) return page(400, 'Sign-in failed', 'The response came from an unexpected sign-in service.', retry, clear);
    if (q.has('error')) {
      const denied = q.get('error') === 'access_denied';
      return page(403, 'Sign-in not completed', denied ? 'The sign-in was cancelled or not allowed.' : 'The sign-in service could not complete the sign-in.', retry, clear);
    }
    const code = q.get('code');
    if (!code || code.length > 2048) return page(400, 'Sign-in failed', 'The sign-in response was incomplete.', retry, clear);

    let claims;
    try {
      const d = await discovery();
      let res;
      try {
        res = await fetchImpl(d.token_endpoint, {
          method: 'POST', redirect: 'error', signal: AbortSignal.timeout(fetchTimeoutMs),
          headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
          body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${origin}${basePath}/callback`, client_id: clientId, code_verifier: pre.verifier }),
        });
      } catch {
        throw new GatekeepError('token request failed', 'token-exchange');
      }
      const text = await res.text();
      if (!res.ok || text.length > MAX_BODY) throw new GatekeepError('token exchange refused', 'token-exchange');
      let tok;
      try {
        tok = JSON.parse(text);
      } catch {
        throw new GatekeepError('token response is not JSON', 'token-exchange');
      }
      claims = await verifyIdToken(tok?.id_token, { nonce: pre.nonce }); // access_token and refresh_token are ignored, never stored
    } catch (e) {
      const unreachable = e instanceof GatekeepError && ['discovery', 'jwks'].includes(e.code);
      return unreachable ? unavailable(clear) : page(403, 'Sign-in failed', 'We could not verify that sign-in. Start again.', retry, clear);
    }

    const email = String(claims.email ?? '').toLowerCase();
    const emailVerified = claims.email_verified === true;
    const verdict = normalizePolicy(await allow({ email, emailVerified, sub: claims.sub, claims }));
    const out = `<form method="post" action="${basePath}/logout"><button>Sign out of the sign-in service</button></form>`;
    if (!verdict) return page(403, 'Not allowed', `${email || 'This account'} does not have access here.`, out, clear);
    const name = display(claims, email || claims.sub);
    try {
      await onSignIn?.({ sub: claims.sub, email, name, role: verdict.role, claims }, req);
    } catch {
      return page(403, 'Not allowed', 'This account could not be set up here.', out, clear);
    }

    // Rotation: every login mints a new session id; any session this browser already holds is revoked.
    const previous = await sessionFromRequest(req).catch(() => null);
    if (previous) await store.del(await sessionKey(previous.sid));
    const sid = randomToken(32);
    const exp = now() + sessionTtlMs;
    const smallClaims = JSON.stringify(claims).length <= 4096 ? claims : { sub: claims.sub, email, email_verified: emailVerified };
    await store.set(await sessionKey(sid), { schema: 1, sub: claims.sub, email, emailVerified, name, role: verdict.role, claims: smallClaims, schema: 1, iat: now(), exp });
    const h = new Headers({ location: safeReturnTo(pre.returnTo, { origin, basePath }), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
    h.append('set-cookie', sessionCookie(secure, await sign(secret, SESSION_PURPOSE, `${sid}.${Math.floor(exp / 1000)}`), Math.floor(sessionTtlMs / 1000)));
    h.append('set-cookie', preCookie(secure, '', 0));
    return new Response(null, { status: 303, headers: h });
  }

  async function logout(req) {
    const origin = originOf(req);
    const secure = origin.startsWith('https:');
    const s = await sessionFromRequest(req).catch(() => null);
    if (s) await store.del(await sessionKey(s.sid));
    let to = postLogoutPath;
    if (rpLogout) {
      try {
        const d = await discovery();
        if (d.end_session_endpoint) {
          const u = new URL(d.end_session_endpoint);
          u.searchParams.set('client_id', clientId);
          u.searchParams.set('post_logout_redirect_uri', `${origin}${postLogoutPath}`);
          to = u.toString();
        }
      } catch {
        // issuer unreachable: local sign-out only
      }
    }
    const h = new Headers({ location: to, 'cache-control': 'no-store' });
    h.append('set-cookie', sessionCookie(secure, '', 0));
    return new Response(null, { status: 303, headers: h });
  }

  async function handle(req) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '');
    const route = path.startsWith(`${basePath}/`) ? path.slice(basePath.length + 1) : null;
    if (!route || !Object.hasOwn(ROUTES, route)) return json({ error: 'not-found', message: 'No such route.' }, 404);
    const method = req.method.toUpperCase() === 'HEAD' ? 'GET' : req.method.toUpperCase();
    if (!ROUTES[route].includes(method)) return json({ error: 'method-not-allowed', message: `Use ${ROUTES[route].join(' or ')}.` }, 405, { allow: ROUTES[route].join(', ') });
    switch (route) {
      case 'login':
        if (req.method.toUpperCase() === 'HEAD') return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } }); // never mint state for a HEAD
        return login(req, url);
      case 'callback':
        return callback(req, url);
      case 'logout': {
        if (method === 'GET') return page(200, 'Sign out?', 'You will be signed out of this site and the sign-in service.', `<form method="post" action="${basePath}/logout"><button>Sign out</button></form>`);
        return guard(req) ?? logout(req);
      }
      case 'me': {
        const u = await auth(req);
        return json({ user: u ? { sub: u.sub, email: u.email, name: u.name, role: u.role } : null });
      }
      default:
        return page(200, 'Signed out', 'You are signed out.', `<p><a href="${basePath}/login">Sign in again</a></p>`);
    }
  }

  async function handler(req) {
    try {
      return await handle(req);
    } catch {
      return json({ error: 'server-error', message: 'Something went wrong.' }, 500);
    }
  }

  return {
    handler,
    auth,
    requireUser,
    guard,
    csrfOk,
    loginUrl,
    verifyIdToken,
    redirectUri: `${fixedOrigin ?? ''}${basePath}/callback`,
    async revokeUser(sub) {
      await store.set(await versionKey(sub), { schema: 1, revokedBefore: now() });
    },
    async sweep() {
      let n = 0;
      for (const prefix of ['session/', 'pre/']) {
        for (const k of await store.list(prefix)) {
          const r = await store.get(k);
          if (r && !(r.exp > now())) {
            await store.del(k);
            n++;
          }
        }
      }
      return n;
    },
  };
}
