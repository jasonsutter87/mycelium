// Sign-in end to end: a real http server around createAuth(), a real fake Gatekeep (copied unchanged from launchkit)
// as the issuer, and a tiny cookie-jar browser. Nothing is mocked in between.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuth } from "../src/auth.ts";
import { fakeGatekeep } from "./helpers/fake-gatekeep.js";

const SECRET = "t".repeat(48);
const cleanups: (() => Promise<void> | void)[] = [];
after(async () => { for (const c of cleanups) await c(); });

async function setup(email = "me@example.com") {
  const fake = await fakeGatekeep({ clientId: "mycelium", user: { sub: "u1", email } });
  const dir = mkdtempSync(join(tmpdir(), "myc-auth-"));
  let server!: Server;
  await new Promise<void>((r) => { server = createServer((req, res) => void gate(req, res)).listen(0, "127.0.0.1", r); });
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  fake.redirectUris.add(base + "/auth/callback");
  const auth = createAuth({ issuer: fake.url, clientId: "mycelium", allowedEmails: ["me@example.com"] }, base, dir, SECRET);
  // The same order serve.ts uses: /auth/* to the kit, then the user, then the CSRF guard on POSTs.
  async function gate(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) {
    const p = new URL(req.url!, base).pathname;
    if (p.startsWith("/auth/")) return auth.handle(req, res);
    const user = await auth.user(req);
    if (!user) return void res.writeHead(401).end("sign in first");
    if (req.method === "POST" && !auth.guard(req, res)) return;
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ email: user.email }));
  }
  cleanups.push(() => fake.close(), () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }), () => rmSync(dir, { recursive: true, force: true }));
  return { fake, base, dir, browser: () => browser() };
}

/** A cookie-jar browser that follows redirects by hand, so every hop is visible. */
function browser() {
  const jar = new Map<string, string>();
  const send = async (url: string, init: RequestInit = {}) => {
    const res = await fetch(url, { ...init, redirect: "manual", headers: { ...(init.headers as object), cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } });
    for (const c of res.headers.getSetCookie()) {
      const [kv, ...attrs] = c.split(";"); const i = kv.indexOf("=");
      if (/max-age=0/i.test(attrs.join(";")) || kv.slice(i + 1) === "") jar.delete(kv.slice(0, i)); else jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return res;
  };
  /** Visit /auth/login and let the issuer approve; returns the callback URL it redirects the browser to. */
  const approve = async (base: string) => {
    const login = await send(base + "/auth/login");
    const authz = await fetch(login.headers.get("location")!, { redirect: "manual" });
    return authz.headers.get("location")!;
  };
  const signIn = async (base: string) => send(await approve(base));
  return { jar, send, approve, signIn };
}

test("an allowed email signs in, and the session works on the app's routes", async () => {
  const t = await setup();
  const b = t.browser();
  assert.equal((await b.send(t.base + "/api/x")).status, 401);
  const res = await b.signIn(t.base);
  assert.equal(res.status, 303);
  const r = await b.send(t.base + "/api/x");
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { email: "me@example.com" });
});

test("a disallowed email is refused: no session", async () => {
  const t = await setup("stranger@example.com");
  const b = t.browser();
  const res = await b.signIn(t.base);
  assert.equal(res.status, 403);
  assert.ok(![...b.jar.keys()].some((k) => k.endsWith("lk_session")));
  assert.equal((await b.send(t.base + "/api/x")).status, 401);
});

test("a forged state is refused (login CSRF): the attacker's callback URL does not sign the victim in", async () => {
  const t = await setup();
  const attacker = t.browser(), victim = t.browser();
  const attackerCallback = await attacker.approve(t.base); // valid code + state, bound to the attacker's browser
  // The victim's browser never started this login: no pre-auth cookie at all.
  assert.ok((await victim.send(attackerCallback)).status >= 400);
  // The victim started a login of their own, then is lured to the attacker's callback.
  await victim.send(t.base + "/auth/login");
  assert.ok((await victim.send(attackerCallback)).status >= 400);
  assert.equal((await victim.send(t.base + "/api/x")).status, 401);
  assert.equal(t.fake.hits.token, 0, "the code was never exchanged");
});

test("sign-out revokes the session, even for a replayed cookie", async () => {
  const t = await setup();
  const b = t.browser();
  await b.signIn(t.base);
  const saved = new Map(b.jar);
  const out = await b.send(t.base + "/auth/logout", { method: "POST", headers: { origin: t.base } });
  assert.equal(out.status, 303);
  assert.equal((await b.send(t.base + "/api/x")).status, 401);
  const replay = t.browser();
  for (const [k, v] of saved) replay.jar.set(k, v);
  assert.equal((await replay.send(t.base + "/api/x")).status, 401);
});

test("a cross-site POST on the app's routes is refused, a same-origin one passes", async () => {
  const t = await setup();
  const b = t.browser();
  await b.signIn(t.base);
  assert.equal((await b.send(t.base + "/api/x", { method: "POST", headers: { origin: "https://evil.example" } })).status, 403);
  assert.equal((await b.send(t.base + "/api/x", { method: "POST", headers: { "sec-fetch-site": "cross-site" } })).status, 403);
  assert.equal((await b.send(t.base + "/api/x", { method: "POST", headers: { origin: t.base } })).status, 200);
});

test("/auth/me returns the profile and never a token", async () => {
  const t = await setup();
  const b = t.browser();
  await b.signIn(t.base);
  const r = await b.send(t.base + "/auth/me");
  const text = await r.text();
  assert.deepEqual(JSON.parse(text), { user: { sub: "u1", email: "me@example.com", name: "me", role: "user" } });
  const stored = readFileSync(join(t.dir, "auth.json"), "utf8");
  for (const tok of t.fake.issued) assert.ok(!text.includes(tok) && !stored.includes(tok), "no issued token in /me or on disk");
});
