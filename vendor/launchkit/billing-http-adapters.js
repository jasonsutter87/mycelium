// Thin shims from the Web-standard handler (src/billing-http.js) to the frameworks that are not already Web.
// Bun, Deno, Cloudflare Workers and Netlify Functions v2 already speak (Request) => Response: use the handler as is.

const MAX_BODY = 1024 * 1024;

/** node:http and Express. Buffers the RAW request body (a webhook's signature covers the exact bytes).
 *  Express: mount it BEFORE express.json(), or on its own path: app.use('/api/billing', toNodeHandler(handler)).
 *  If a body parser already ran, the raw bytes are used when the parser kept them (req.rawBody), otherwise a webhook
 *  cannot verify and gets a 400; checkout and portal are rebuilt from the parsed object. */
export function toNodeHandler(handler, { maxBody = MAX_BODY, trustProxy = false } = {}) {
  return async function nodeHandler(req, res) {
    try {
      const chunks = [];
      let size = 0;
      let body;
      if (req.readableEnded) {
        body = req.rawBody ?? (Buffer.isBuffer(req.body) || typeof req.body === 'string' ? req.body : req.body && typeof req.body === 'object' ? JSON.stringify(req.body) : undefined);
      } else {
        for await (const c of req) {
          size += c.length;
          if (size > maxBody) {
            res.statusCode = 413;
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ error: 'invalid', message: 'Body too large.' }));
            req.destroy?.();
            return;
          }
          chunks.push(c);
        }
        body = Buffer.concat(chunks);
      }
      const proto = (trustProxy && String(req.headers['x-forwarded-proto'] ?? '').split(',')[0].trim()) || (req.socket?.encrypted ? 'https' : 'http');
      const host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host || 'localhost';
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (Array.isArray(v)) for (const x of v) headers.append(k, x);
        else if (v != null) headers.set(k, String(v));
      }
      const method = req.method ?? 'GET';
      const request = new Request(`${proto}://${host}${req.originalUrl ?? req.url ?? '/'}`, {
        method,
        headers,
        ...(method === 'GET' || method === 'HEAD' || body === undefined ? {} : { body }),
      });
      const response = await handler(request);
      res.statusCode = response.status;
      for (const [k, v] of response.headers) if (k !== 'set-cookie') res.setHeader(k, v);
      const cookies = response.headers.getSetCookie?.() ?? [];
      if (cookies.length) res.setHeader('set-cookie', cookies);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader('content-type', 'application/json');
      }
      res.end(JSON.stringify({ error: 'server-error', message: 'Something went wrong.' }));
    }
  };
}

/** Netlify Functions v2: `export default toNetlifyHandler(handler)`; also `export const config = netlifyConfig()`. */
export const toNetlifyHandler = (handler) => (req) => handler(req);
export const netlifyConfig = (basePath = '/api/billing') => ({ path: [`${basePath}/*`] });

/** Bun.serve / Deno.serve / Cloudflare Workers: `fetch: toFetchHandler(handler)`. Already Web: returned as is. */
export const toFetchHandler = (handler) => handler;

/** Next.js App Router, app/api/billing/[...path]/route.ts: `export const { GET, POST } = toNextRoute(handler)`. */
export const toNextRoute = (handler) => {
  const h = (req) => handler(req);
  return { GET: h, POST: h };
};
