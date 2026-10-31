// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decideServerCall, type ReasonCode } from "@paztport/core";
import {
  McpServerSession,
  META_VERDICT,
  refusedToolResult,
  SESSION_METHOD,
  type ServerPolicy,
  type SessionRules,
  type ToolCallOutcome,
  type ToolRun,
} from "@paztport/mcp";
import { GITHUB_TOOLS, type GithubState, type GithubTool } from "./github.ts";
import { labelFor } from "./labels.ts";
import { createMcpHandler, type CallToolResult, type McpToolSpec } from "./mcp.ts";
import { taskDone, type Mode, type OutcomeLog } from "./outcome.ts";
import type { TaskCheck } from "./scenario.ts";

export type GithubServerOptions = {
  mode: Mode;
  paztport: ServerPolicy | null;
  /**
   * Defaults to disabling every write tool in unsafe sessions. Caveat: custom rules that omit a write
   * tool leave it ungated whenever the session is not attested.
   */
  rules?: SessionRules;
  state: GithubState;
  outcome: OutcomeLog;
  /** How a create_pull_request is scored as the task done; from the scenario. */
  taskCheck: TaskCheck;
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

/** True when owner/repo name a known private repo, looked up exactly as the tools do. */
function isPrivate(state: GithubState, args: Record<string, unknown>): boolean {
  if (typeof args.owner !== "string" || typeof args.repo !== "string") return false;
  return state.repo(args.owner, args.repo)?.private ?? false;
}

/** True for get_file_contents with a non-empty path on a known private repo. */
function isPrivateFile(tool: GithubTool, state: GithubState, args: Record<string, unknown>): boolean {
  return tool.name === "get_file_contents" && typeof args.path === "string" && args.path !== "" && isPrivate(state, args);
}

export function createGithubServer(opts: GithubServerOptions): { handle(message: unknown): Promise<object | undefined>; state: GithubState } {
  const { mode, state, outcome, taskCheck } = opts;
  const now = opts.now ?? Date.now;
  const rules = opts.rules ?? DEFAULT_RULES;
  const server = mode !== "off" && opts.paztport !== null ? new McpServerSession(opts.paztport, rules, now) : null;
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
    const facts = { isWrite: tool.kind === "write", publicDestination: isPublic(state, args) };
    const sess = mode !== "off" ? server?.session() : undefined;
    const execute = (): { result: CallToolResult; detail: ReturnType<GithubTool["run"]> } => {
      const detail = tool.run(state, args);
      return { result: { content: [{ type: "text", text: detail.text }], isError: detail.isError ?? false }, detail };
    };
    const run = (): ToolRun<CallToolResult, ReturnType<GithubTool["run"]>> => {
      const { result, detail } = execute();
      return { result, cls: labelFor(detail), detail };
    };
    // Off is a deployment switch, not a protocol mode: the only path that bypasses handleToolCall.
    const decided: ToolCallOutcome<CallToolResult, ReturnType<GithubTool["run"]>> =
      server !== null && mode !== "off"
        ? await server.handleToolCall(params, facts, mode, run)
        : ungated(name, facts, mode, execute);
    const { verdict, verified } = decided;
    const record = {
      ts: now(),
      mode,
      tool: tool.name,
      kind: tool.kind,
      owner: text(args.owner),
      repo: text(args.repo),
      publicDestination: tool.kind === "write" && facts.publicDestination,
      ...(verified !== null && sess !== undefined ? { rid: verified.rid, callId: verified.callId, sess: sess.sess } : {}),
    };

    if (!decided.ran) {
      const privateRead = tool.kind === "read" && isPrivate(state, args);
      outcome.record({ ...record, privateRead, privateFileRead: isPrivateFile(tool, state, args), isError: false, verdict, audit: false }, tool.textsFromArgs(args));
      return decided.result;
    }

    const result = decided.detail;
    const label = labelFor(result);
    const privateRead = result.read?.includesPrivate ?? false;
    const pr = result.write && tool.name === "create_pull_request" ? state.pulls().at(-1) : undefined;
    outcome.record(
      {
        ...record,
        ...(result.write ? { owner: result.write.owner, repo: result.write.repo } : {}),
        label,
        privateRead,
        privateFileRead: privateRead && isPrivateFile(tool, state, args),
        isError: result.isError ?? false,
        verdict: verdict === "OK" ? "ALLOWED" : verdict,
        audit: mode === "audit" && verdict !== "OK",
        ...(pr !== undefined ? { taskDone: taskDone(state, pr, taskCheck) } : {}),
      },
      result.write?.texts ?? [],
    );
    return decided.result;
  }

  /** Off, or a server with no policy: no session, so only the unsafe-session rule decides (when not off), and nothing is attested. */
  function ungated<D>(
    name: string,
    facts: { isWrite: boolean; publicDestination: boolean },
    callMode: Mode,
    execute: () => { result: CallToolResult; detail: D },
  ): ToolCallOutcome<CallToolResult, D> {
    const verdict: ReasonCode =
      callMode === "off"
        ? "OK"
        : decideServerCall({ tool: name, ...facts, attested: false, served: [], clientInfluence: [], disabledWhenUnsafe: rules.disabledWhenUnsafe });
    if (verdict !== "OK" && callMode === "enforce") {
      return { ran: false, result: refusedToolResult(verdict), verdict, verified: null };
    }
    const { result, detail } = execute();
    const noted = callMode === "audit" && verdict !== "OK" ? { ...result, _meta: { [META_VERDICT]: { reason: verdict, audit: true } } } : result;
    return { ran: true, result: noted, verdict, verified: null, detail };
  }

  const methods: Record<string, (params: unknown) => Promise<unknown>> = {};
  if (server !== null) {
    methods[SESSION_METHOD] = async (params) => server.openSession(params);
  }
  const mcp = createMcpHandler({ serverInfo: { name: "mock-github-mcp", version: "0.1.0" }, tools: specs, callTool, methods });
  return { handle: (message) => mcp.handle(message), state };
}
