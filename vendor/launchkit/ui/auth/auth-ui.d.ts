import type { Labels, AuthStore } from './core.js';
export * from './core.js';
export const LkAuth: { defaultBase: string; navigate(url: string): void; reset(): void };
export function storeFor(base?: string): AuthStore;
export interface SignInDetail { base: string; returnTo: string }
export interface UserDetail { base: string; user: import('./core.js').AuthUser | null }
export interface ErrorDetail { base: string; status: number; message: string }
declare class LkBase extends HTMLElement { base: string; labels: Partial<Labels> | null }
export class LkSignIn extends LkBase {}
export class LkAccount extends LkBase {}
export class LkSignedIn extends HTMLElement {}
export class LkSignedOut extends HTMLElement {}
declare global {
  interface HTMLElementTagNameMap { 'lk-sign-in': LkSignIn; 'lk-account': LkAccount; 'lk-signed-in': LkSignedIn; 'lk-signed-out': LkSignedOut }
  interface DocumentEventMap { 'lk-auth:user': CustomEvent<UserDetail>; 'lk-auth:error': CustomEvent<ErrorDetail>; 'lk-auth:signin': CustomEvent<SignInDetail>; 'lk-auth:signout': CustomEvent<{ base: string }> }
}
