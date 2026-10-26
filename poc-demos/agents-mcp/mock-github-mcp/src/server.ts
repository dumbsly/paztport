// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { influenceClasses, type InfluenceClass, type InfluenceEntry, type ReasonCode } from "@paztport/core";
import { SESSION_METHOD } from "@paztport/mcp";
import { GITHUB_TOOLS, type GithubState, type GithubTool } from "./github.ts";
import { labelFor } from "./labels.ts";
import { createMcpHandler, type CallToolResult, type McpToolSpec } from "./mcp.ts";
import { taskDone, type Mode, type OutcomeLog } from "./outcome.ts";
import { META_VERDICT, PaztportServer, type ServerPaztportConfig, type Session, type SessionRules } from "./paztport.ts";
import { influenceDecision } from "./rules.ts";
import type { TaskCheck } from "./scenario.ts";

export type GithubServerOptions = {
  mode: Mode;
  paztport: ServerPaztportConfig | null;
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

/**
 * The classes the influence rule sees in an attested session: the client's verified influence
 * plus every class this server served in the session. The union only adds classes, so the server
 * is stricter, never looser, than the harness: a client that fails to record a private (or
 * third-party) label cannot launder it past the rule.
 */
function contextClasses(influence: InfluenceEntry[], session: Session): Set<InfluenceClass> {
  return new Set([...influenceClasses(influence), ...session.served]);
}

export function createGithubServer(opts: GithubServerOptions): { handle(message: unknown): Promise<object | undefined>; state: GithubState } {
  const { mode, state, outcome, taskCheck } = opts;
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
    const sess = mode !== "off" ? server?.session() : undefined;
    if (mode !== "off") {
      if (server !== null && sess?.status === "attested") {
        call = server.checkCall(params);
        verdict = call.reason;
        if (verdict === "OK") verdict = influenceDecision(tool, isPublic(state, args), contextClasses(call.influence, sess));
      } else if (rules.disabledWhenUnsafe.includes(tool.name)) {
        verdict = "UNSAFE_SESSION";
      }
    }
    const verified = call !== null && call.reason === "OK" ? call : null;
    const record = {
      ts: now(),
      mode,
      tool: tool.name,
      kind: tool.kind,
      owner: text(args.owner),
      repo: text(args.repo),
      publicDestination: tool.kind === "write" && isPublic(state, args),
      ...(verified !== null && sess !== undefined ? { rid: verified.rid, callId: verified.callId, sess: sess.sess } : {}),
    };

    if (verdict !== "OK" && mode === "enforce") {
      const privateRead = tool.kind === "read" && isPrivate(state, args);
      outcome.record({ ...record, privateRead, privateFileRead: isPrivateFile(tool, state, args), isError: false, verdict, audit: false }, tool.textsFromArgs(args));
      return {
        content: [{ type: "text", text: `Paztport refused this call: ${verdict}` }],
        isError: true,
        _meta: { [META_VERDICT]: { reason: verdict } },
      };
    }

    const result = tool.run(state, args);
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
    const mcpResult: CallToolResult = { content: [{ type: "text", text: result.text }], isError: result.isError ?? false };
    if (mode === "audit" && verdict !== "OK") mcpResult._meta = { [META_VERDICT]: { reason: verdict, audit: true } };
    if (server !== null && verified !== null) {
      return server.attest(verified.session, mcpResult, { rid: verified.rid, callId: verified.callId, name, args: params.arguments ?? {} }, label);
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
