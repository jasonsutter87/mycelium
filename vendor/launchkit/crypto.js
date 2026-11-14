// Small Web Crypto helpers shared by the modules. Web Crypto (not node:crypto) so everything runs the same
// on Node 20+, Netlify Functions and Edge, Cloudflare Workers and Bun.

const enc = new TextEncoder();

export const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

export function base64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Unguessable token: `bytes` of randomness, base64url. 32 bytes = 256 bits. */
export const randomToken = (bytes = 32) => base64url(crypto.getRandomValues(new Uint8Array(bytes)));

/** Sortable-ish random id for records (time prefix keeps listings roughly in creation order). */
export const randomId = () => `${Date.now().toString(36)}${randomToken(9)}`;

export const sha256 = async (text) => toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));

const keys = new Map();
async function hmacKey(secret) {
  if (!keys.has(secret)) keys.set(secret, crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']));
  return keys.get(secret);
}

/** HMAC-SHA256 of `text`, hex. Different `purpose` strings keep one secret's uses apart. */
export const hmac = async (secret, purpose, text) => toHex(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(`${purpose}:${text}`)));

/** Constant-time string comparison. */
export function safeEqual(a, b) {
  a = String(a);
  b = String(b);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

/** `${value}.${signature}` and back. Used for cookies that carry an id. */
export const sign = async (secret, purpose, value) => `${value}.${await hmac(secret, purpose, value)}`;
export async function unsign(secret, purpose, signed) {
  const s = String(signed ?? '');
  const dot = s.lastIndexOf('.');
  if (dot < 1) return null;
  const value = s.slice(0, dot);
  return safeEqual(s.slice(dot + 1), await hmac(secret, purpose, value)) ? value : null;
}

export function requireSecret(secret, who) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error(`${who}: secret must be a string of at least 32 characters`);
}
