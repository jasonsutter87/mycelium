// `mycelium serve`: the report, live, with Fix buttons.
// Listens on 127.0.0.1 only. Every API call needs a random per-run token that only the served page knows,
// and the Host header must be localhost, so other websites can't drive it (CSRF / DNS rebinding).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import type { DatabaseSync } from "node:sqlite";
import { findings } from "./graph.ts";
import { renderHtmlReport } from "./report.ts";
import { applyFixes, planFixes } from "./fix.ts";
import { checkAll } from "./osv.ts";
import { scanRoots } from "./scan.ts";
import { enrich } from "./depsdev.ts";
import { pullProject, syncPrs } from "./prs.ts";

export function serve(db: DatabaseSync, port: number) {
  // Stable across restarts (open tabs keep working); only pages served by this machine ever see it.
  let token = (db.prepare("SELECT value FROM settings WHERE key = 'serve_token'").get() as { value: string } | undefined)?.value;
  if (!token) {
    token = randomBytes(24).toString("hex");
    db.prepare("INSERT INTO settings (key, value) VALUES ('serve_token', ?)").run(token);
  }
  let busy = false; // one fix at a time: they run package managers and git

  const server = createServer(async (req, res) => {
    const host = req.headers.host ?? "";
    if (![`127.0.0.1:${port}`, `localhost:${port}`, `mycelium.localhost:${port}`].includes(host)) return send(res, 403, { error: "bad host" });

    try {
      if (req.method === "GET" && (req.url === "/" || req.url?.startsWith("/?"))) {
        const html = renderHtmlReport(db, findings(db), { token }); // render first: an error must not hit a half-sent page
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        return res.end(html);
      }
      if (req.method !== "POST" || !req.url?.startsWith("/api/")) return send(res, 404, { error: "not found" });
      if (req.headers["x-mycelium-token"] !== token) return send(res, 403, { error: "bad token" });
      const body = await readBody(req);
      if (["/api/plan", "/api/apply", "/api/pull"].includes(req.url) && typeof body.project !== "string") {
        return send(res, 400, { error: "which project? (missing project name)" });
      }

      if (req.url === "/api/plan") return send(res, 200, planFixes(db, body.project, { minSeverity: body.minSeverity }));

      if (req.url === "/api/pull") {
        if (busy) return send(res, 409, { error: "another job is running" });
        busy = true;
        try {
          const row = db.prepare("SELECT path FROM projects WHERE name = ?").get(body.project) as { path: string } | undefined;
          if (!row) return send(res, 400, { error: "unknown project" });
          const r = pullProject(db, row.path);
          if (r.pulled.length) {
            await checkAll(db);
            await syncPrs(db);
          }
          return send(res, 200, r);
        } finally {
          busy = false;
        }
      }

      if (req.url === "/api/apply" || req.url === "/api/refresh") {
        if (busy) return send(res, 409, { error: "another job is running" });
        busy = true;
        try {
          if (req.url === "/api/refresh") {
            const roots = JSON.parse((db.prepare("SELECT value FROM settings WHERE key = 'roots'").get() as any)?.value ?? "[]");
            scanRoots(db, roots);
            await checkAll(db);
            await enrich(db);
            await syncPrs(db);
            return send(res, 200, { ok: true });
          }
          const plan = planFixes(db, body.project, { minSeverity: body.minSeverity });
          const r = applyFixes(db, plan, {
            only: body.only, allowMajor: !!body.allowMajor, verify: !!body.verify, pr: !!body.pr,
          });
          if (r.applied.length) await checkAll(db);
          if (r.prs.length) await syncPrs(db);
          return send(res, 200, r);
        } finally {
          busy = false;
        }
      }
      send(res, 404, { error: "not found" });
    } catch (e) {
      send(res, 400, { error: (e as Error).message });
    }
  });

  server.listen(port, "127.0.0.1", () => {
    const url = `http://mycelium.localhost:${port}/`;
    console.log(`🍄 Mycelium at ${url}  (Ctrl-C to stop)`);
    if (process.platform === "darwin" && !process.env.MYCELIUM_NO_OPEN) execFile("open", [url]);
  });
}

function send(res: ServerResponse, status: number, data: unknown) {
  if (res.headersSent) return void res.end(); // never crash the server over a late error
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (ch) => {
      raw += ch;
      if (raw.length > 1e6) reject(new Error("body too large"));
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("invalid JSON"));
      }
    });
  });
}
