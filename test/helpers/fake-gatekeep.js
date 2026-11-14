// A local fake gatekeep: discovery, JWKS, authorize, token and logout on http.createServer (port 0), with real keys from
// Web Crypto. It enforces what the real one does (exact redirect_uri, PKCE S256, single-use codes) and has knobs for
// minting hostile tokens. Nothing here touches the network beyond 127.0.0.1.
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';

const enc = new TextEncoder();
export const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
export const b64uJson = (o) => b64u(enc.encode(JSON.stringify(o)));

const GEN = {
  EdDSA: { gen: () => crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']), sign: { name: 'Ed25519' } },
  ES256: { gen: () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']), sign: { name: 'ECDSA', hash: 'SHA-256' } },
  RS256: { gen: () => crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']), sign: { name: 'RSASSA-PKCS1-v1_5' } },
};

export async function fakeGatekeep({ clientId = 'app', redirectUris = [], user, advertise, endSession = true, algs = ['EdDSA'] } = {}) {
  const f = {
    clientId,
    redirectUris: new Set(redirectUris),
    user: { sub: 'user-1', email: 'me@example.com', email_verified: true, ...user },
    hits: { discovery: 0, jwks: 0, authorize: 0, token: 0, logout: 0 },
    issued: [], // every id/access/refresh token handed out, to prove they never leak
    tokenRequests: [],
    logouts: [],
    lastAuthorize: null,
    authorizeError: null, // e.g. 'access_denied'
    sendIss: null, // add &iss=... to the callback (mix-up tests)
    discoveryOverride: null, // (doc) => doc
    forge: null, // (ctx) => id_token string
    tamper: null, // (ctx) => void, mutates ctx.header / ctx.claims (and ctx.kid, the key that signs) before signing
    down: false, // discovery answers 503
  };
  const keys = new Map(); // kid -> { alg, priv, jwk, published }
  const active = {};
  let n = 0;
  async function addKey(alg, { publish = true, makeActive = true } = {}) {
    const pair = await GEN[alg].gen();
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const kid = `k${++n}`;
    keys.set(kid, { alg, priv: pair.privateKey, jwk: { ...jwk, kid, alg, use: 'sig', key_ops: undefined, ext: undefined }, published: publish });
    if (makeActive) active[alg] = kid;
    return kid;
  }
  for (const a of algs) await addKey(a);
  f.rotate = (opts = {}) => addKey(opts.alg ?? 'EdDSA', opts);
  f.publicJwk = (kid) => keys.get(kid).jwk;
  f.activeKid = (alg = 'EdDSA') => active[alg];

  /** Sign header.payload with a held key. */
  async function signWith(kid, header, claims) {
    const k = keys.get(kid);
    const input = `${b64uJson(header)}.${b64uJson(claims)}`;
    const sig = await crypto.subtle.sign(GEN[k.alg].sign, k.priv, enc.encode(input));
    return `${input}.${b64u(new Uint8Array(sig))}`;
  }
  f.signWith = signWith;
  /** A token with whatever header and signature you hand it. */
  f.compact = (header, claims, sig = '') => `${b64uJson(header)}.${b64uJson(claims)}.${sig}`;

  const now = () => Math.floor(Date.now() / 1000);
  f.baseClaims = (nonce) => ({ iss: f.url, sub: f.user.sub, aud: clientId, exp: now() + 300, iat: now(), email: f.user.email, email_verified: f.user.email_verified, ...(nonce ? { nonce } : {}) });

  const codes = new Map();
  const json = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };

  const server = createServer(async (req, res) => {
    const u = new URL(req.url, f.url);
    if (u.pathname === '/.well-known/openid-configuration') {
      f.hits.discovery++;
      if (f.down) return json(res, 503, { error: 'down' });
      let doc = {
        issuer: f.url, authorization_endpoint: `${f.url}/authorize`, token_endpoint: `${f.url}/token`, jwks_uri: `${f.url}/jwks.json`,
        ...(endSession ? { end_session_endpoint: `${f.url}/logout` } : {}),
        response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
        id_token_signing_alg_values_supported: advertise ?? algs, code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
      };
      if (f.discoveryOverride) doc = f.discoveryOverride(doc);
      return json(res, 200, doc);
    }
    if (u.pathname === '/jwks.json') {
      f.hits.jwks++;
      return json(res, 200, { keys: [...keys.values()].filter((k) => k.published).map((k) => k.jwk) });
    }
    if (u.pathname === '/authorize') {
      f.hits.authorize++;
      const q = Object.fromEntries(u.searchParams);
      f.lastAuthorize = q;
      const bad = (m) => json(res, 400, { error: 'invalid_request', error_description: m });
      if (q.client_id !== clientId) return bad('client_id');
      if (!f.redirectUris.has(q.redirect_uri)) return bad('redirect_uri not registered');
      if (q.response_type !== 'code' || q.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge ?? '')) return bad('pkce');
      if (!q.state || !q.nonce) return bad('state and nonce');
      const back = new URL(q.redirect_uri);
      if (f.authorizeError) {
        back.searchParams.set('error', f.authorizeError);
        back.searchParams.set('error_description', '<script>alert(1)</script>');
        back.searchParams.set('state', q.state);
      } else {
        const code = randomBytes(24).toString('base64url');
        codes.set(code, { redirect_uri: q.redirect_uri, challenge: q.code_challenge, nonce: q.nonce, used: false, user: { ...f.user } });
        back.searchParams.set('code', code);
        back.searchParams.set('state', q.state);
      }
      if (f.sendIss) back.searchParams.set('iss', f.sendIss);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (u.pathname === '/token' && req.method === 'POST') {
      f.hits.token++;
      let body = '';
      for await (const c of req) body += c;
      const form = Object.fromEntries(new URLSearchParams(body));
      f.tokenRequests.push(form);
      const c = codes.get(form.code);
      const bad = (e) => json(res, 400, { error: e });
      if (form.grant_type !== 'authorization_code' || !c || c.used) return bad('invalid_grant');
      c.used = true;
      if (form.client_id !== clientId || form.redirect_uri !== c.redirect_uri || 'client_secret' in form) return bad('invalid_grant');
      if (createHash('sha256').update(form.code_verifier ?? '').digest('base64url') !== c.challenge) return bad('invalid_grant');
      const ctx = { kid: active[algs[0]], header: { alg: algs[0], typ: 'JWT', kid: active[algs[0]] }, claims: { ...f.baseClaims(c.nonce), sub: c.user.sub, email: c.user.email, email_verified: c.user.email_verified }, nonce: c.nonce };
      f.tamper?.(ctx);
      const idToken = f.forge ? await f.forge(ctx) : await signWith(ctx.kid ?? ctx.header.kid, ctx.header, ctx.claims);
      const access = `ACCESS.${randomBytes(18).toString('base64url')}`;
      const refresh = `REFRESH.${randomBytes(18).toString('base64url')}`;
      f.issued.push(idToken, access, refresh);
      return json(res, 200, { access_token: access, token_type: 'Bearer', expires_in: 300, id_token: idToken, refresh_token: refresh });
    }
    if (u.pathname === '/logout') {
      f.hits.logout++;
      f.logouts.push(Object.fromEntries(u.searchParams));
      const to = u.searchParams.get('post_logout_redirect_uri');
      if (to) {
        res.writeHead(302, { location: to });
        return res.end();
      }
      res.writeHead(200);
      return res.end('signed out');
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  f.url = `http://127.0.0.1:${server.address().port}`;
  f.close = () => new Promise((r) => (server.closeAllConnections?.(), server.close(r)));
  return f;
}
