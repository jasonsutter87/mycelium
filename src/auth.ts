// Sign-in through Gatekeep (OpenID Connect + passkeys). Gatekeep is a public
// client provider: authorization code + PKCE (S256), no client secret, EdDSA
// (Ed25519) id_tokens checked against its JWKS with Node's own crypto.
//
// ~/.mycelium/config.json:
//   "auth": { "issuer": "https://<gatekeep issuer>", "clientId": "mycelium", "allowedEmails": ["you@example.com"] },
//   "baseUrl": "http://localhost:4400"
// Register the app in Gatekeep with redirect URI <baseUrl>/auth/callback.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString('base64url');
const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest();
const SESSION_DAYS = 14;
const COOKIE = 'mycelium_session';
const clean = (s: unknown) => String(s).replace(/[<>&"]/g, '');

export interface AuthConfig { issuer: string; clientId: string; allowedEmails: string[] }
export interface User { email: string; sub: string; exp: number }

export function createAuth(cfg: AuthConfig, baseUrl: string, dataDir: string) {
  if (!cfg.issuer || !cfg.clientId) throw new Error('auth: issuer and clientId are required');
  if (!cfg.allowedEmails?.length) throw new Error('auth: list at least one email in allowedEmails');
  const issuer = cfg.issuer.replace(/\/$/, ''), clientId = cfg.clientId;
  const redirectUri = baseUrl.replace(/\/$/, '') + '/auth/callback';
  const secure = baseUrl.startsWith('https://');
  const allowed = new Set(cfg.allowedEmails.map(e => e.toLowerCase()));

  let discovery: any = null, jwks: any = null, jwksAt = 0;
  async function disco() {
    if (!discovery) {
      const r = await fetch(issuer + '/.well-known/openid-configuration');
      if (!r.ok) throw new Error('Gatekeep discovery failed: HTTP ' + r.status);
      discovery = await r.json();
      if (discovery.issuer !== issuer) throw new Error('Gatekeep issuer mismatch: ' + discovery.issuer);
    }
    return discovery;
  }
  async function keyFor(kid: string) {
    const find = () => jwks?.keys?.find((k: any) => k.kid === kid);
    if (!find() || Date.now() - jwksAt > 3600e3) { jwks = await (await fetch((await disco()).jwks_uri)).json(); jwksAt = Date.now(); }
    const k = find();
    if (!k || k.kty !== 'OKP' || k.crv !== 'Ed25519') return null;
    return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' });
  }
  async function verify(token: string, nonce: string) {
    const parts = String(token).split('.');
    if (parts.length !== 3) throw new Error('malformed id_token');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (header.alg !== 'EdDSA') throw new Error('unexpected alg');
    const key = await keyFor(header.kid);
    if (!key) throw new Error('unknown signing key');
    if (!crypto.verify(null, Buffer.from(parts[0] + '.' + parts[1]), key, Buffer.from(parts[2], 'base64url'))) throw new Error('bad signature');
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== issuer) throw new Error('wrong issuer');
    if (!aud.includes(clientId)) throw new Error('wrong audience');
    if (!(claims.exp > Date.now() / 1000 - 60)) throw new Error('token expired');
    if (claims.nonce !== nonce) throw new Error('nonce mismatch');
    return claims;
  }

  const pending = new Map<string, { verifier: string; nonce: string; exp: number }>();
  const file = path.join(dataDir, 'sessions.json');
  let sessions: Record<string, User> = {};
  try { sessions = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* none yet */ }
  const saveSessions = () => {
    for (const [k, s] of Object.entries(sessions)) if (s.exp < Date.now()) delete sessions[k];
    fs.writeFileSync(file, JSON.stringify(sessions), { mode: 0o600 });
  };
  const cookieOf = (req: IncomingMessage) => (req.headers.cookie || '').match(new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]+)`))?.[1];
  const setCookie = (v: string, maxAge: number) => `${COOKIE}=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
  const page = (title: string, body: string) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font:16px system-ui;max-width:420px;margin:15vh auto;padding:0 16px"><h1 style="font-size:20px">${title}</h1><p>${body}</p>`;

  return {
    user(req: IncomingMessage): User | null {
      const c = cookieOf(req), s = c ? sessions[b64u(sha256(c))] : null;
      return s && s.exp > Date.now() ? s : null;
    },
    async login(_req: IncomingMessage, res: ServerResponse) {
      const d = await disco();
      const state = b64u(crypto.randomBytes(16)), verifier = b64u(crypto.randomBytes(32)), nonce = b64u(crypto.randomBytes(16));
      for (const [k, v] of pending) if (v.exp < Date.now()) pending.delete(k);
      pending.set(state, { verifier, nonce, exp: Date.now() + 600e3 });
      const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope: 'openid email',
        state, nonce, code_challenge: b64u(sha256(verifier)), code_challenge_method: 'S256' });
      res.writeHead(302, { Location: d.authorization_endpoint + '?' + q }).end();
    },
    async callback(req: IncomingMessage, res: ServerResponse) {
      const q = new URL(req.url || '/', baseUrl).searchParams, st = q.get('state') || '';
      const p = pending.get(st); pending.delete(st);
      const fail = (m: string) => res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' }).end(page('Sign-in failed', m));
      if (!p || p.exp < Date.now()) return fail('That sign-in expired. <a href="/auth/login">Try again</a>.');
      if (q.get('error')) return fail('Gatekeep said: ' + clean(q.get('error')));
      try {
        const d = await disco();
        const r = await fetch(d.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'authorization_code', code: q.get('code') || '', redirect_uri: redirectUri, client_id: clientId, code_verifier: p.verifier }) });
        const tok: any = await r.json();
        if (!r.ok || !tok.id_token) throw new Error(tok.error || 'token exchange failed');
        const claims = await verify(tok.id_token, p.nonce);
        const email = String(claims.email || '').toLowerCase();
        if (!claims.email_verified || !allowed.has(email)) return fail(`${clean(email || 'This account')} isn't allowed here. <a href="/auth/logout">Sign out</a>.`);
        const c = b64u(crypto.randomBytes(32));
        sessions[b64u(sha256(c))] = { email, sub: claims.sub, exp: Date.now() + SESSION_DAYS * 864e5 };
        saveSessions();
        res.writeHead(302, { Location: '/', 'Set-Cookie': setCookie(c, SESSION_DAYS * 86400) }).end();
      } catch (e) { fail('Could not verify the sign-in: ' + clean((e as Error).message)); }
    },
    async logout(req: IncomingMessage, res: ServerResponse) {
      const c = cookieOf(req);
      if (c) { delete sessions[b64u(sha256(c))]; saveSessions(); }
      let to = '/auth/login';
      try { const d = await disco(); if (d.end_session_endpoint) to = d.end_session_endpoint + '?post_logout_redirect_uri=' + encodeURIComponent(baseUrl + '/'); } catch { /* offline */ }
      res.writeHead(302, { Location: to, 'Set-Cookie': setCookie('', 0) }).end();
    },
  };
}
