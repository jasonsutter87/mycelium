// One JSON file as the store (Node, Bun; any host with a writable disk). Single process only.
// Writes go through a serialized queue and land atomically: write a temp file next to the target, then rename it.
// A crash mid-write leaves the old file intact. Needs node:fs, so it is not for Workers or Edge.

import { readFile, writeFile, rename, mkdir, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';

export function jsonFile(path) {
  let data = null;
  let chain = Promise.resolve();
  let n = 0;

  async function load() {
    if (data) return;
    try {
      data = JSON.parse(await readFile(path, 'utf8'));
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not an object');
    } catch (e) {
      if (e.code !== 'ENOENT') throw new Error(`jsonFile: ${path} is not a JSON object store (${e.message})`);
      data = {};
    }
  }
  async function persist() {
    await mkdir(dirname(path), { recursive: true });
    const tmp = `${path}.${process.pid}.${++n}.tmp`;
    try {
      await writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
      await rename(tmp, path);
    } catch (e) {
      await unlink(tmp).catch(() => {});
      throw e;
    }
  }
  /** Run `fn` after every earlier operation finished; a failed one does not block the next. */
  function queued(fn) {
    const run = chain.then(async () => {
      await load();
      return fn();
    });
    chain = run.catch(() => {});
    return run;
  }

  return {
    get: (k) => queued(() => (k in data ? structuredClone(data[k]) : null)),
    set: (k, v) =>
      queued(async () => {
        const had = Object.hasOwn(data, k) ? { v: data[k] } : null;
        data[k] = structuredClone(v);
        try {
          await persist();
        } catch (e) {
          if (had) data[k] = had.v;
          else delete data[k];
          throw e;
        }
      }),
    del: (k) =>
      queued(async () => {
        if (!Object.hasOwn(data, k)) return;
        const old = data[k];
        delete data[k];
        try {
          await persist();
        } catch (e) {
          data[k] = old;
          throw e;
        }
      }),
    list: (prefix = '') => queued(() => Object.keys(data).filter((k) => k.startsWith(prefix)).sort()),
  };
}
