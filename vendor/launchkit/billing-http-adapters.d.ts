type Handler = (req: Request) => Response | Promise<Response>;
export function toNodeHandler(handler: Handler, options?: { maxBody?: number; trustProxy?: boolean }): (req: any, res: any) => Promise<void>;
export function toNetlifyHandler(handler: Handler): (req: Request, context?: unknown) => Response | Promise<Response>;
export function netlifyConfig(basePath?: string): { path: string[] };
export function toFetchHandler(handler: Handler): Handler;
export function toNextRoute(handler: Handler): { GET: (req: Request, ctx?: unknown) => Response | Promise<Response>; POST: (req: Request, ctx?: unknown) => Response | Promise<Response> };
