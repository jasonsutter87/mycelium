// The reviewer's read-only tools as an MCP server, for when it runs through Claude Code. Started once per review, for one
// commit of one repo, both fixed on the command line: nothing the model sends can point it anywhere else.
//
// Nothing here may write to stdout except the MCP transport.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { MAX_TOOL_CALLS, runTool } from "./review.ts";

const [repo, sha] = process.argv.slice(2);
if (!repo || !/^[0-9a-f]{7,64}$/.test(sha ?? "")) {
  console.error("usage: review-tools <clone> <commit>");
  process.exit(2);
}

const server = new McpServer({ name: "review", version: "1.0.0" });
let calls = 0;
const handler = (name: string) => async (input: Record<string, unknown>) => {
  if (++calls > MAX_TOOL_CALLS) return { isError: true, content: [{ type: "text" as const, text: "That's the limit on reads for one review. Give your answer now." }] };
  try {
    return { content: [{ type: "text" as const, text: await runTool(repo, sha, name, input) }] };
  } catch (e) {
    return { isError: true, content: [{ type: "text" as const, text: String((e as any).stderr || (e as Error).message).slice(0, 500) }] };
  }
};

server.registerTool("read_file", { description: "Read one file as it is in this PR's head commit.", inputSchema: { path: z.string().describe("Path from the repo root") } }, handler("read_file"));
server.registerTool("search", { description: "Find a plain string (not a regex) across this PR's head commit. Use it to find callers and other users of what changed.", inputSchema: { text: z.string(), path: z.string().optional().describe("Optional folder or file to limit the search to") } }, handler("search"));
server.registerTool("list_files", { description: "List files in this PR's head commit.", inputSchema: { path: z.string().optional().describe("Optional folder") } }, handler("list_files"));

await server.connect(new StdioServerTransport());
