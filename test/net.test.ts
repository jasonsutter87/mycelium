import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { fetchRetry } from "../src/net.ts";

const real = globalThis.fetch;
afterEach(() => { globalThis.fetch = real; });
const blip = () => Object.assign(new TypeError("fetch failed"), { cause: { code: "EAI_AGAIN" } });

test("retries a thrown network error, then returns the response", async () => {
  let calls = 0;
  globalThis.fetch = (async () => { if (++calls < 3) throw blip(); return new Response("ok"); }) as typeof fetch;
  const r = await fetchRetry("https://api.example.test/x", {}, { baseMs: 1 });
  assert.equal(await r.text(), "ok");
  assert.equal(calls, 3);
});

test("gives up after the limit and names the host and the real reason", async () => {
  let calls = 0;
  globalThis.fetch = (async () => { calls++; throw blip(); }) as typeof fetch;
  await assert.rejects(fetchRetry("https://api.example.test/x", {}, { tries: 3, baseMs: 1 }), /api\.example\.test after 3 tries \(EAI_AGAIN\)/);
  assert.equal(calls, 3);
});

test("HTTP errors are returned to the caller, not retried here", async () => {
  let calls = 0;
  globalThis.fetch = (async () => { calls++; return new Response("no", { status: 500 }); }) as typeof fetch;
  assert.equal((await fetchRetry("https://api.example.test/x", {}, { baseMs: 1 })).status, 500);
  assert.equal(calls, 1);
});
