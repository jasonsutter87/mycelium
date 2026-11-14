import type { Store } from './store.js';

export interface GatekeepUser {
  sub: string;
  email: string;
  name: string;
  role: string;
}
export interface PolicyInput {
  email: string;
  emailVerified: boolean;
  sub: string;
  claims: Record<string, unknown>;
}
export type PolicyResult = boolean | { role?: string };
export type Policy = (input: PolicyInput) => PolicyResult | Promise<PolicyResult>;

export interface GatekeepAuthOptions {
  /** 'https://id.gatekeepauth.com'. https, or http on a loopback host for development. */
  issuer: string;
  /** As registered in gatekeep's clients.toml. */
  clientId: string;
  /** 32+ characters. Signs the session and pre-auth cookies. */
  secret: string;
  store: Store;
  /** Required: who may sign in, and as what role. Use allowlist(), openSignup() or ownersAndGuests(). */
  allow: Policy;
  /** Public origin, e.g. 'https://app.example.com'. Default: the request's own. Set it in production. */
  origin?: string;
  basePath?: string;
  scope?: string;
  sessionTtlMs?: number;
  preAuthTtlMs?: number;
  clockSkewSec?: number;
  maxIdTokenAgeSec?: number;
  algs?: Array<'EdDSA' | 'ES256' | 'RS256'>;
  recheckPolicy?: boolean;
  rpLogout?: boolean;
  postLogoutPath?: string;
  defaultReturnTo?: string;
  onSignIn?: (user: GatekeepUser & { claims: Record<string, unknown> }, req: Request) => void | Promise<void>;
  discoveryTtlMs?: number;
  jwksTtlMs?: number;
  fetchTimeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
}

export interface GatekeepAuth {
  /** The routes under basePath: /login, /callback, /logout, /me, /signed-out. */
  handler(req: Request): Promise<Response>;
  /** The signed-in user for this request, or null. Never throws. */
  auth(req: Request): Promise<GatekeepUser | null>;
  /** A user, or a Response to return (401 JSON for APIs, 303 to login for pages, 403 for a CSRF failure). */
  requireUser(req: Request): Promise<GatekeepUser | Response>;
  guard(req: Request): Response | null;
  csrfOk(req: Request): boolean;
  loginUrl(returnTo?: string): string;
  verifyIdToken(jwt: string, opts: { nonce: string }): Promise<Record<string, unknown>>;
  /** The redirect URI to register in clients.toml (complete only when `origin` is set). */
  redirectUri: string;
  revokeUser(sub: string): Promise<void>;
  sweep(): Promise<number>;
}

export class GatekeepError extends Error {
  code: 'config' | 'discovery' | 'jwks' | 'token-exchange' | 'invalid-token' | 'denied';
  constructor(message: string, code?: GatekeepError['code']);
}
export function createGatekeepAuth(options: GatekeepAuthOptions): GatekeepAuth;
export function safeReturnTo(raw: unknown, opts: { origin: string; basePath?: string; fallback?: string }): string;
export function emailList(v: string | string[] | undefined): string[];
export function allowlist(list: string[] | (() => string[])): Policy;
export function openSignup(opts?: { role?: string }): Policy;
export function ownersAndGuests(opts: { owners: string[] | (() => string[]); guests?: boolean; guestRole?: string; ownerRole?: string }): Policy;
export function billingAuth(auth: (req: Request) => Promise<GatekeepUser | null>): (req: Request) => Promise<{ orgId: string; email: string } | null>;
