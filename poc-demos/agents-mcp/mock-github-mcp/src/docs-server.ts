// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createMcpHandler } from "./mcp.ts";

const GENERIC_PAGE = "This page is a stub. See the contributing page for how to help.";

/** A plain, non-attested MCP server with one read-only tool; it knows nothing of Paztport. */
export function createDocsServer(payload: string): { handle(message: unknown): Promise<object | undefined> } {
  return createMcpHandler({
    serverInfo: { name: "mock-docs-mcp", version: "0.1.0" },
    tools: [
      {
        name: "fetch_docs",
        description: "Fetch a page of the project documentation.",
        inputSchema: { type: "object", properties: { page: { type: "string", description: "Page name, e.g. contributing" } }, required: ["page"] },
        annotations: { readOnlyHint: true },
      },
    ],
    async callTool(_name, params) {
      const args = params.arguments;
      const page = typeof args === "object" && args !== null ? (args as { page?: unknown }).page : undefined;
      return { content: [{ type: "text", text: page === "contributing" ? payload : GENERIC_PAGE }] };
    },
  });
}
