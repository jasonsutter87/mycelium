// The storage contract every module uses. Any key-value store with JSON values fits:
//
//   get(key)          → value or null
//   set(key, value)   → stores a JSON-serializable value
//   del(key)          → removes it (missing is fine)
//   list(prefix)      → keys starting with prefix
//
// Adapters are a few lines each: files, Netlify Blobs, Cloudflare KV, Redis, a SQL table. Keys use "/" as a
// separator and only [A-Za-z0-9._@-/] characters, so they're safe as file paths and blob keys.
// Writes are last-write-wins; the modules are written so a lost race costs at most a counter tick.

/** In-memory store, for tests and single-process prototypes. */
export function memoryStore() {
  const m = new Map();
  return {
    async get(k) {
      return m.has(k) ? structuredClone(m.get(k)) : null;
    },
    async set(k, v) {
      m.set(k, structuredClone(v));
    },
    async del(k) {
      m.delete(k);
    },
    async list(prefix = '') {
      return [...m.keys()].filter((k) => k.startsWith(prefix)).sort();
    },
  };
}

/** View of a store under a prefix, so one app's launchkit data can't collide with its own keys. */
export function prefixed(store, prefix) {
  const p = prefix.endsWith('/') ? prefix : `${prefix}/`;
  return {
    get: (k) => store.get(p + k),
    set: (k, v) => store.set(p + k, v),
    del: (k) => store.del(p + k),
    list: async (pre = '') => (await store.list(p + pre)).map((k) => k.slice(p.length)),
  };
}

/** Make a value safe to use inside a key. Case is kept (ids are case-sensitive); normalize emails before. */
export const keyPart = (s) => String(s).replace(/[^A-Za-z0-9._@-]/g, '_').slice(0, 200);
