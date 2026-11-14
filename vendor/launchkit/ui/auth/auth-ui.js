// launchkit auth UI: <lk-sign-in>, <lk-account>, <lk-signed-in>, <lk-signed-out>.
// No build, no dependencies. Style them with --lk-* custom properties (same ones as the billing UI).
import { DEFAULT_BASE, mergeLabels, initials, avatarHue, getStore, resetStore } from './core.js';

export * from './core.js';

const doc = () => globalThis.document;

/** Events go to `document`: lk-auth:user, :error, :signin (cancelable), :signout (cancelable). */
function emit(name, detail) {
  const d = doc();
  if (!d) return true;
  return d.dispatchEvent(new CustomEvent(`lk-auth:${name}`, { detail, cancelable: name === 'signin' || name === 'signout' }));
}

export const LkAuth = {
  defaultBase: DEFAULT_BASE,
  /** Where the browser goes to sign in. Replace it to open a popup or a modal. */
  navigate: (url) => globalThis.location.assign(url),
  reset: resetStore,
};

export const storeFor = (base = LkAuth.defaultBase) => getStore(base, { emit, navigate: (u) => LkAuth.navigate(u) });

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const CSS = `
:host {
  --_accent: var(--lk-accent, #2a47bd);
  --_accent-fg: var(--lk-accent-fg, #ffffff);
  --_bg: var(--lk-bg, #ffffff);
  --_fg: var(--lk-fg, #1b1e27);
  --_muted: var(--lk-muted, #596072);
  --_border: var(--lk-border, #d6d9e1);
  --_tint: var(--lk-tint, #eef1fc);
  --_radius: var(--lk-radius, 10px);
  --_font: var(--lk-font, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif);
  display: inline-block;
  position: relative;
  font: 400 1rem/1.5 var(--_font);
  color: var(--_fg);
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :host(:not([theme="light"])) {
    --_accent: var(--lk-accent, #9db0ff); --_accent-fg: var(--lk-accent-fg, #0e1330); --_bg: var(--lk-bg, #1a1d26);
    --_fg: var(--lk-fg, #eceef4); --_muted: var(--lk-muted, #a4abbb); --_border: var(--lk-border, #333847); --_tint: var(--lk-tint, #232a45);
    color-scheme: dark;
  }
}
:host([theme="dark"]) {
  --_accent: var(--lk-accent, #9db0ff); --_accent-fg: var(--lk-accent-fg, #0e1330); --_bg: var(--lk-bg, #1a1d26);
  --_fg: var(--lk-fg, #eceef4); --_muted: var(--lk-muted, #a4abbb); --_border: var(--lk-border, #333847); --_tint: var(--lk-tint, #232a45); color-scheme: dark;
}
:host([hidden]) { display: none; }
*, *::before, *::after { box-sizing: border-box; }
button { font: inherit; cursor: pointer; border-radius: calc(var(--_radius) * .8); min-height: 2.75rem; padding: .5rem 1.1rem; border: 1px solid var(--_border); background: transparent; color: var(--_fg); }
button:focus-visible { outline: 3px solid var(--_accent); outline-offset: 2px; }
button.primary { background: var(--_accent); border-color: var(--_accent); color: var(--_accent-fg); font-weight: 600; }
button:disabled { cursor: progress; opacity: .6; }
@media (prefers-reduced-motion: no-preference) {
  button { transition: background-color .15s, border-color .15s, opacity .15s; }
  button:not(:disabled):hover { border-color: var(--_accent); }
}
.who { display: inline-flex; align-items: center; gap: .6rem; padding: .25rem .75rem .25rem .25rem; min-height: 2.75rem; border-radius: 999px; }
.avatar { width: 2.25rem; height: 2.25rem; border-radius: 50%; display: grid; place-items: center; font-size: .875rem; font-weight: 650; color: #fff; background: hsl(var(--hue, 220) 45% 38%); flex: none; }
.name { max-width: 12rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.menu { position: absolute; right: 0; top: calc(100% + .35rem); z-index: 10; min-width: 14rem; padding: .9rem; display: grid; gap: .75rem; background: var(--_bg); border: 1px solid var(--_border); border-radius: var(--_radius); box-shadow: 0 8px 24px rgb(0 0 0 / .12); }
.menu[hidden] { display: none; }
.menu p { margin: 0; color: var(--_muted); font-size: .875rem; overflow-wrap: anywhere; }
.menu p strong { display: block; color: var(--_fg); font-weight: 600; }
.menu form { margin: 0; }
.menu button { width: 100%; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
`;

class LkElement extends (globalThis.HTMLElement ?? class {}) {
  static get observedAttributes() {
    return ['base', 'theme', 'return-to'];
  }

  constructor() {
    super();
    this._labels = null;
    this._open = false;
  }

  get base() {
    return this.getAttribute('base') || LkAuth.defaultBase;
  }

  get store() {
    return storeFor(this.base);
  }

  get labels() {
    return mergeLabels(this._labels);
  }

  set labels(v) {
    this._labels = v;
    this.update();
  }

  connectedCallback() {
    if (!this.shadowRoot) {
      this.attachShadow({ mode: 'open' });
      this.shadowRoot.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && this._open) {
          this.close();
          this.shadowRoot.querySelector('[data-act="toggle"]')?.focus();
        }
      });
    }
    this._unsub = this.store.subscribe(() => this.update());
    this._onDoc = (e) => {
      if (this._open && !e.composedPath().includes(this)) this.close();
    };
    doc()?.addEventListener('click', this._onDoc);
    this.update();
  }

  disconnectedCallback() {
    this._unsub?.();
    doc()?.removeEventListener('click', this._onDoc);
  }

  attributeChangedCallback() {
    if (this.isConnected) {
      this._unsub?.();
      this._unsub = this.store.subscribe(() => this.update());
      this.update();
    }
  }

  close() {
    this._open = false;
    this.update();
  }

  update() {
    if (!this.shadowRoot) return;
    const s = this.store.getState();
    const html = this.view(this.labels, s);
    this.shadowRoot.innerHTML = `<style>${CSS}</style>${html}`;
    this.shadowRoot.querySelectorAll('[data-act]').forEach((el) => el.addEventListener('click', (e) => this.act(el.dataset.act, e)));
  }
}

// ---------- <lk-sign-in> ----------
class LkSignIn extends LkElement {
  act(name) {
    if (name === 'signin') this.store.signIn(this.getAttribute('return-to') || undefined);
  }

  view(L, s) {
    const show = s.loaded && !s.user;
    this.hidden = !show && !this.hasAttribute('always');
    if (this.hidden) return '';
    return `<button class="primary" data-act="signin" ${s.signingIn ? 'disabled aria-busy="true"' : ''}>${esc(s.signingIn ? L.signingIn : L.signIn)}</button>`;
  }
}

// ---------- <lk-account> ----------
class LkAccount extends LkElement {
  act(name) {
    if (name === 'toggle') {
      this._open = !this._open;
      this.update();
      if (this._open) this.shadowRoot.querySelector('.menu button')?.focus();
    }
  }

  view(L, s) {
    this.hidden = !s.user;
    if (!s.user) return '';
    const u = s.user;
    const label = u.name || u.email;
    return `<button class="who" data-act="toggle" aria-haspopup="menu" aria-expanded="${this._open}" aria-label="${esc(`${L.menu}: ${label}`)}">
      <span class="avatar" style="--hue:${avatarHue(u.sub)}" aria-hidden="true">${esc(initials(u))}</span><span class="name">${esc(label)}</span></button>
      <div class="menu" role="menu" ${this._open ? '' : 'hidden'}>
        <p>${esc(L.signedInAs)}<strong>${esc(u.email || u.name)}</strong></p>
        <form method="post" action="${esc(this.store.base)}/logout"><button type="submit" role="menuitem">${esc(L.signOut)}</button></form>
      </div>`;
  }
}

// ---------- <lk-signed-in> / <lk-signed-out>: show their children for one state, nothing while we find out ----------
class LkGate extends (globalThis.HTMLElement ?? class {}) {
  static get observedAttributes() {
    return ['base'];
  }

  get base() {
    return this.getAttribute('base') || LkAuth.defaultBase;
  }

  connectedCallback() {
    this.hidden = true;
    this._unsub = storeFor(this.base).subscribe((s) => {
      this.hidden = !(s.loaded && this.wants(s));
    });
  }

  disconnectedCallback() {
    this._unsub?.();
  }
}
class LkSignedIn extends LkGate {
  wants(s) {
    return !!s.user;
  }
}
class LkSignedOut extends LkGate {
  wants(s) {
    return !s.user;
  }
}

const defs = { 'lk-sign-in': LkSignIn, 'lk-account': LkAccount, 'lk-signed-in': LkSignedIn, 'lk-signed-out': LkSignedOut };
if (typeof customElements !== 'undefined' && globalThis.HTMLElement) {
  for (const [name, cls] of Object.entries(defs)) if (!customElements.get(name)) customElements.define(name, cls);
}

export { LkSignIn, LkAccount, LkSignedIn, LkSignedOut };
