// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { SESSION_METHOD, type ReasonCode } from "@paztport/path-attest";
import { GITHUB_TOOLS, type GithubState, type GithubTool } from "./github.ts";
import { labelFor } from "./labels.ts";
import { createMcpHandler, type CallToolResult, type McpToolSpec } from "./mcp.ts";
import { typoFixed, type Mode, type OutcomeLog } from "./outcome.ts";
import { META_VERDICT, PaztportServer, type ServerPaztportConfig, type SessionRules } from "./paztport.ts";
import { influenceDecision } from "./rules.ts";

export type GithubServerOptions = {
  mode: Mode;
  paztport: ServerPaztportConfig | null;
  rules?: SessionRules;
  state: GithubState;
  outcome: OutcomeLog;
  now?: () => number;
};

/** By default every write tool is disabled in an unsafe session. */
const DEFAULT_RULES: SessionRules = { disabledWhenUnsafe: GITHUB_TOOLS.filter((t) => t.kind === "write").map((t) => t.name) };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const text = (v: unknown): string => (typeof v === "string" ? v : "");

/** True when owner/repo name a known public repo, looked up exactly as the tools do. */
function isPublic(state: GithubState, args: Record<string, unknown>): boolean {
  if (typeof args.owner !== "string" || typeof args.repo !== "string") return false;
  const r = state.repo(args.owner, args.repo);
  return r !== undefined && !r.private;
}

export function createGithubServer(opts: GithubServerOptions): { handle(message: unknown): Promise<object | undefined>; state: GithubState } {
  const { mode, state, outcome } = opts;
  const now = opts.now ?? Date.now;
  const rules = opts.rules ?? DEFAULT_RULES;
  const server = mode !== "off" && opts.paztport !== null ? new PaztportServer(opts.paztport, rules, now) : null;
  const tools = new Map<string, GithubTool>(GITHUB_TOOLS.map((t) => [t.name, t]));
  const specs: McpToolSpec[] = GITHUB_TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
    annotations: { readOnlyHint: t.kind === "read" },
  }));

  async function callTool(name: string, params: Record<string, unknown>): Promise<CallToolResult> {
    const tool = tools.get(name)!;
    const args = isObject(params.arguments) ? params.arguments : {};
    let verdict: ReasonCode = "OK";
    let call: ReturnType<PaztportServer["checkCall"]> | null = null;
    if (mode !== "off") {
      const sess = server?.session();
      if (server !== null && sess?.status === "attested") {
        call = server.checkCall(params);
        verdict = call.reason;
        if (verdict === "OK") verdict = influenceDecision(tool, isPublic(state, args), call.influence);
      } else if (rules.disabledWhenUnsafe.includes(tool.name)) {
        verdict = "UNSAFE_SESSION";
      }
    }
    const record = {
      ts: now(),
      mode,
      tool: tool.name,
      owner: text(args.owner),
      repo: text(args.repo),
      publicDestination: isPublic(state, args),
    };

    if (verdict !== "OK" && mode === "enforce") {
      if (tool.kind === "write") outcome.record({ ...record, verdict, audit: false }, tool.textsFromArgs(args));
      return {
        content: [{ type: "text", text: `Paztport refused this call: ${verdict}` }],
        isError: true,
        _meta: { [META_VERDICT]: { reason: verdict } },
      };
    }

    const result = tool.run(state, args);
    if (result.write) {
      const pr = tool.name === "create_pull_request" ? state.pulls().at(-1) : undefined;
      outcome.record(
        {
          ...record,
          owner: result.write.owner,
          repo: result.write.repo,
          verdict: verdict === "OK" ? "ALLOWED" : verdict,
          audit: mode === "audit" && verdict !== "OK",
          ...(pr !== undefined ? { typoFixed: typoFixed(state, pr) } : {}),
        },
        result.write.texts,
      );
    }
    const mcpResult: CallToolResult = { content: [{ type: "text", text: result.text }], isError: result.isError ?? false };
    if (mode === "audit" && verdict !== "OK") mcpResult._meta = { [META_VERDICT]: { reason: verdict, audit: true } };
    if (server !== null && call !== null && call.reason === "OK") {
      return server.attest(mcpResult, { rid: call.rid, callId: call.callId, name, args: params.arguments ?? {} }, labelFor(result));
    }
    // unsafe sessions, off mode and failed checks: unattested
    return mcpResult;
  }

  const methods: Record<string, (params: unknown) => Promise<unknown>> = {};
  if (server !== null) {
    methods[SESSION_METHOD] = async (params) => server.openSession(params);
  }
  const mcp = createMcpHandler({ serverInfo: { name: "mock-github-mcp", version: "0.1.0" }, tools: specs, callTool, methods });
  return { handle: (message) => mcp.handle(message), state };
}
