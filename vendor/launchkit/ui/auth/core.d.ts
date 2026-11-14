export const DEFAULT_BASE: string;
export interface AuthUser { sub: string; email: string; name: string; role: string }
export interface Labels { signIn: string; signingIn: string; account: string; menu: string; signedInAs: string; signOut: string; retry: string; unavailable: string }
export const DEFAULT_LABELS: Readonly<Labels>;
export function mergeLabels(custom?: Partial<Labels> | null): Labels;
export function fmt(tpl: string, vars?: Record<string, unknown>): string;
export function initials(user: Partial<AuthUser> | null | undefined): string;
export function avatarHue(sub: string | null | undefined): number;
export function currentPath(loc?: { pathname?: string; search?: string; hash?: string }): string;
export function signInUrl(base?: string, returnTo?: string): string;
export class AuthUiError extends Error { status: number }
export function createClient(opts?: { base?: string; fetch?: typeof fetch }): { root: string; me(): Promise<{ user: AuthUser | null }> };
export function postForm(action: string, doc?: Document): void;
export interface AuthState { user: AuthUser | null; loaded: boolean; loading: boolean; error: { message: string; status: number } | null; signingIn: boolean }
export interface AuthStore {
  base: string;
  getState(): AuthState;
  subscribe(fn: (s: AuthState) => void): () => void;
  refresh(): Promise<AuthUser | null>;
  /** Navigates to <base>/login?returnTo=... (returns the URL, or null when an lk-auth:signin listener cancelled). */
  signIn(returnTo?: string): string | null;
  /** Submits a POST form to <base>/logout. */
  signOut(): void;
}
export function createStore(opts?: { base?: string; fetch?: typeof fetch; emit?: (name: string, detail: unknown) => boolean; navigate?: (url: string) => void; submit?: (action: string) => void }): AuthStore;
export function getStore(base?: string, deps?: object): AuthStore;
export function resetStore(): void;
