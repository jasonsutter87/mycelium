// launchkit auth UI: the parts with no DOM in them. Labels, avatar helpers, the same-origin path check, and the fetch
// client + shared store the components and the React hook sit on. The browser only ever sees GET <base>/me (profile JSON,
// never a token), a navigation to <base>/login, and a form POST to <base>/logout.

export const DEFAULT_BASE = '/auth';

export const DEFAULT_LABELS = Object.freeze({
  signIn: 'Sign in with a passkey',
  signingIn: 'Opening sign-in…',
  account: 'Account',
  menu: 'Account menu',
  signedInAs: 'Signed in as',
  signOut: 'Sign out',
  retry: 'Try again',
  unavailable: 'We could not check your sign-in.',
});

export const mergeLabels = (custom) => ({ ...DEFAULT_LABELS, ...(custom && typeof custom === 'object' ? custom : {}) });
export const fmt = (tpl, vars = {}) => String(tpl).replace(/\{(\w+)\}/g, (_, k) => (k in vars ? String(vars[k]) : `{${k}}`));

/** Up to two capital letters for the avatar: from the name when it has one, else from the email. */
export function initials(user) {
  const source = String(user?.name || user?.email || '?').split('@')[0].trim();
  const words = source.split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0][0] + words[words.length - 1][0] : (words[0] || '?').slice(0, 2);
  return letters.toUpperCase();
}

/** A stable hue (0-359) from the account id, so each person keeps one avatar colour. */
export function avatarHue(sub) {
  let h = 0;
  for (const ch of String(sub ?? '')) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return h % 360;
}

/** The path (and query) to come back to after sign-in: same-origin only. The server checks again; this keeps the URL tidy. */
export function currentPath(loc = globalThis.location) {
  if (!loc) return '/';
  const p = `${loc.pathname || '/'}${loc.search || ''}${loc.hash || ''}`;
  return p.startsWith('/') && !p.startsWith('//') ? p : '/';
}

export const signInUrl = (base = DEFAULT_BASE, returnTo) => `${String(base).replace(/\/+$/, '')}/login${returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ''}`;

export class AuthUiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = 'AuthUiError';
    this.status = status;
  }
}

/** GET <base>/me -> { user } | { user: null }. Throws AuthUiError when the server cannot be asked. */
export function createClient({ base = DEFAULT_BASE, fetch: f = (...a) => globalThis.fetch(...a) } = {}) {
  const root = String(base).replace(/\/+$/, '');
  return {
    root,
    async me() {
      let res;
      try {
        res = await f(`${root}/me`, { credentials: 'same-origin', headers: { accept: 'application/json' } });
      } catch {
        throw new AuthUiError('network', 0);
      }
      if (!res.ok) throw new AuthUiError('server', res.status);
      const body = await res.json().catch(() => null);
      const u = body?.user;
      if (u == null) return { user: null };
      if (typeof u !== 'object' || typeof u.sub !== 'string') throw new AuthUiError('bad-response', res.status);
      return { user: { sub: u.sub, email: String(u.email ?? ''), name: String(u.name ?? ''), role: String(u.role ?? 'user') } };
    },
  };
}

/** Sign out is a real form POST so the browser follows the redirect to the issuer and back. */
export function postForm(action, doc = globalThis.document) {
  if (!doc) return;
  const form = doc.createElement('form');
  form.method = 'POST';
  form.action = action;
  form.style.display = 'none';
  doc.body.append(form);
  form.submit();
}

/** One store per base, shared by every element and hook on the page, so /me is fetched once. */
export function createStore({ base = DEFAULT_BASE, fetch: f, emit = () => true, navigate = (u) => globalThis.location.assign(u), submit = postForm } = {}) {
  const client = createClient({ base, fetch: f });
  let state = { user: null, loaded: false, loading: false, error: null, signingIn: false };
  const subs = new Set();
  let inflight = null;
  const set = (patch) => {
    state = { ...state, ...patch };
    for (const fn of subs) fn(state);
  };
  const store = {
    base: client.root,
    getState: () => state,
    subscribe(fn) {
      subs.add(fn);
      if (!state.loaded && !state.loading) store.refresh();
      return () => subs.delete(fn);
    },
    refresh() {
      inflight ??= (async () => {
        set({ loading: true, error: null });
        try {
          const { user } = await client.me();
          set({ user, loaded: true, loading: false });
          emit('user', { base: client.root, user });
        } catch (e) {
          set({ loaded: true, loading: false, error: { message: e.message, status: e.status } });
          emit('error', { base: client.root, status: e.status, message: e.message });
        }
        return state.user;
      })().finally(() => {
        inflight = null;
      });
      return inflight;
    },
    signIn(returnTo = currentPath()) {
      if (!emit('signin', { base: client.root, returnTo })) return null;
      set({ signingIn: true });
      const url = signInUrl(client.root, returnTo);
      navigate(url);
      return url;
    },
    signOut() {
      if (!emit('signout', { base: client.root })) return;
      submit(`${client.root}/logout`);
    },
  };
  return store;
}

const stores = new Map();
export const getStore = (base = DEFAULT_BASE, deps = {}) => {
  const key = String(base).replace(/\/+$/, '');
  if (!stores.has(key)) stores.set(key, createStore({ base: key, ...deps }));
  return stores.get(key);
};
export const resetStore = () => stores.clear();
