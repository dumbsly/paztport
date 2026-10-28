// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { JSON_RPC_ERROR_CODES, McpClient, McpError, McpTimeoutError, StdioTransport, type Tool } from "@earendil-works/pi-mcp";
import { encode, NonceCache, NONCE_TTL_MS, randomBytes, type InfluenceClass, type SessionReply, type SessionRequest } from "@paztport/core";
import {
  classifySessionError,
  classifySessionReply,
  readToolResult,
  replacementRequest,
  sessionRequest,
  SESSION_METHOD,
  stampToolCall,
  toolCallProof,
  type ResultContext,
  type SessionOutcome,
} from "@paztport/mcp";
import type { ExtensionMode, ServerSpec } from "./config.ts";
import type { EventLog } from "./events.ts";
import { EvidenceLog, type EvidenceRecord } from "./evidence.ts";
import type { InfluenceStore } from "./influence.ts";
import { CLIENT_CHAIN, PI_SVC, readPin, type ClientMaterial } from "./keys.ts";
import { refusalText } from "./refusals.ts";
import type { RunState } from "./runs.ts";

type EvidenceCallParams = Extract<EvidenceRecord, { type: "call" }>["params"];

export type SessionState = "attested" | "unsafe" | "off";

export type CallOutcome = {
  /** Only the remote result's text content (or a local error message); never _meta. */
  text: string;
  isError: boolean;
  details: {
    server: string;
    callId: string;
    rid?: string;
    /** The server's paztport/verdict reason code (a refusal, or an audit-mode note). */
    verdict?: string;
    /** Response verification reason code ("OK" when verified); attested sessions only. */
    verify?: string;
    /** Classes of the verified response labels. */
    labels?: InfluenceClass[];
    /** Influence entry counts per class after this call; never hashes or content. */
    influence: Record<string, number>;
    session: SessionState;
    /** Why the session is not attested (a reason code, no secrets). */
    sessionReason?: string;
    /**
     * Set when this extension produced the outcome itself and recorded no influence for it: a server
     * refusal (its text replaced), a local refusal such as no active run, or a local error. Its text
     * holds no server content, and a restored session skips it.
     */
    refused?: true;
  };
};

const INST = "pi-1";
/** The server hop a verified response must start at. */
const SERVER_ORIGINS = ["mcp-entry"];
const SAFE_CALL_ID = /^[A-Za-z0-9_-]{1,128}$/;
const RPC_ERRORS: Record<number, string> = {
  [JSON_RPC_ERROR_CODES.parseError]: "parse error",
  [JSON_RPC_ERROR_CODES.invalidRequest]: "invalid request",
  [JSON_RPC_ERROR_CODES.methodNotFound]: "method not found",
  [JSON_RPC_ERROR_CODES.invalidParams]: "invalid params",
  [JSON_RPC_ERROR_CODES.internalError]: "internal error",
};

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The text items of a result's content, joined by newlines. */
function textOf(raw: Record<string, unknown>): string {
  const content = Array.isArray(raw.content) ? raw.content : [];
  return content
    .filter((c): c is { type: "text"; text: string } => isObject(c) && c.type === "text" && typeof c.text === "string")
    .map((c) => c.text)
    .join("\n");
}

/** A local message and an event code for a failed request. JSON-RPC error text is server data and is left out. */
function describeError(e: unknown): { message: string; code: string; rpcCode?: number } {
  if (e instanceof McpError) {
    return { message: `JSON-RPC error ${e.code} (${RPC_ERRORS[e.code] ?? "server error"})`, code: "RPC_ERROR", rpcCode: e.code };
  }
  if (e instanceof McpTimeoutError) {
    return { message: e.message, code: "TIMEOUT" };
  }
  return { message: e instanceof Error ? e.message : String(e), code: "TRANSPORT" };
}

/**
 * One MCP server over stdio. In an attested session every tools/call carries the prompt-origin chain,
 * the route proof and the influence it was made under, and every response is verified before its
 * labels are recorded. Unsafe and off sessions send plain calls.
 */
export class ServerConnection {
  private readonly spec: ServerSpec;
  private readonly mode: ExtensionMode;
  private readonly material: ClientMaterial;
  private readonly influence: InfluenceStore;
  private readonly runs: RunState;
  private readonly events: EventLog;
  private readonly evidence: EvidenceLog;
  private readonly now: () => number;
  private readonly responseNonces = new NonceCache(NONCE_TTL_MS);
  private client: McpClient | undefined;
  private transport: StdioTransport | undefined;
  private reply: SessionReply | undefined;
  private state: SessionState = "unsafe";
  private reason: string | undefined = "NOT_CONNECTED";
  private toolList: Tool[] = [];

  constructor(
    spec: ServerSpec,
    mode: ExtensionMode,
    material: ClientMaterial,
    influence: InfluenceStore,
    runs: RunState,
    events: EventLog,
    now: () => number = Date.now,
    evidence: EvidenceLog = new EvidenceLog(undefined),
  ) {
    this.spec = spec;
    this.mode = mode;
    this.material = material;
    this.influence = influence;
    this.runs = runs;
    this.events = events;
    this.now = now;
    this.evidence = evidence;
  }

  /** Spawns the server, runs initialize, the paztport/session handshake (when due) and tools/list. Throws if the server cannot start. */
  async connect(): Promise<void> {
    if (this.client !== undefined) {
      throw new Error(`MCP server "${this.spec.id}" is already connected`);
    }
    const client = new McpClient({ name: "paztport-pi-extension", version: "0.1.0" });
    const transport = new StdioTransport({
      command: this.spec.command,
      ...(this.spec.args !== undefined ? { args: this.spec.args } : {}),
      ...(this.spec.env !== undefined ? { env: this.spec.env } : {}),
      stderr: "pipe",
    });
    this.client = client;
    this.transport = transport;
    try {
      await client.connect(transport);
      await this.handshake(client);
      this.events.emit({ type: "session", server: this.spec.id, status: this.state, ...(this.reason !== undefined ? { reason: this.reason } : {}) });
      this.toolList = await client.listTools();
    } catch (e) {
      this.events.emit({ type: "error", server: this.spec.id, code: "CONNECT_FAILED" });
      await client.close().catch(() => {});
      throw new Error(`MCP server "${this.spec.id}" failed to start: ${describeError(e).message}`);
    }
  }

  private async handshake(client: McpClient): Promise<void> {
    const unsafe = (reason: string) => {
      this.state = "unsafe";
      this.reason = reason;
    };
    this.reason = undefined;
    if (this.mode === "off") {
      this.state = "off";
      return;
    }
    if (!this.spec.attested) {
      return unsafe("NOT_ATTESTED");
    }
    // Read the pin first: without one there is nothing to verify a reply against, so no session is opened.
    let pin: string;
    try {
      if (this.spec.pin === undefined) {
        throw new Error("no pin");
      }
      pin = readPin(this.spec.pin);
    } catch {
      return unsafe("PIN_MISSING");
    }
    if (pin === "") {
      return unsafe("PIN_MISSING");
    }
    const req = sessionRequest({
      signedRoot: this.mode === "no-root" ? null : this.material.signedRoot,
      policyPublicKey: this.material.policyPublicKey,
      keyring: this.material.keyring,
      keyringSig: this.material.keyringSig,
    });
    // Each request that was sent is written to the evidence file, with the raw reply (null when
    // there was none) and the state it left this connection in.
    const record = (request: SessionRequest, raw: unknown, status: "attested" | "unsafe", reason?: string) =>
      this.evidence.write({
        v: 1,
        type: "session",
        server: this.spec.id,
        request,
        reply: raw ?? null,
        pin,
        status,
        ...(reason !== undefined ? { reason } : {}),
      });
    let raw: unknown;
    let outcome: SessionOutcome | undefined;
    try {
      raw = await client.request(SESSION_METHOD, req as unknown as Record<string, unknown>);
    } catch (e) {
      outcome = classifySessionError(e instanceof McpError ? e.code : undefined);
    }
    // "mcp-entry": the server's entry service, as in SERVER_ORIGINS.
    outcome ??= classifySessionReply(raw, req, pin, "mcp-entry", Date.now());
    if (outcome.status === "attested") {
      this.reply = outcome.reply;
      this.state = "attested";
      record(req, raw, "attested");
      return;
    }
    record(req, raw, "unsafe", outcome.reason);
    if (outcome.replaceSession) {
      // The server may hold an attested session this client cannot use; replace it, best effort.
      const replacement = replacementRequest(req);
      let second: unknown;
      try {
        second = await client.request(SESSION_METHOD, replacement as unknown as Record<string, unknown>);
      } catch {
        // stays unsafe
      }
      record(replacement, second, "unsafe", outcome.reason);
    }
    return unsafe(outcome.reason);
  }

  status(): SessionState {
    return this.state;
  }

  tools(): Tool[] {
    return [...this.toolList];
  }

  /** The server's process id, while it runs. */
  get pid(): number | undefined {
    return this.transport?.pid;
  }

  /** Never throws: local refusals, transport and JSON-RPC errors come back as isError outcomes. */
  async call(tool: string, args: Record<string, unknown>, toolCallId: string): Promise<CallOutcome> {
    const server = this.spec.id;
    const callId = SAFE_CALL_ID.test(toolCallId) ? toolCallId : encode(randomBytes(16));
    const session = this.state;
    const details = (extra: Partial<CallOutcome["details"]>): CallOutcome["details"] => ({
      server,
      callId,
      ...extra,
      influence: this.influence.summary(),
      session,
      ...(this.reason !== undefined ? { sessionReason: this.reason } : {}),
    });
    const fail = (message: string, code: string, extra: Partial<CallOutcome["details"]> = {}, rpcCode?: number): CallOutcome => {
      this.events.emit({
        type: "error",
        server,
        tool,
        callId,
        ...(extra.rid !== undefined ? { rid: extra.rid } : {}),
        code,
        ...(rpcCode !== undefined ? { rpcCode } : {}),
      });
      return { text: `MCP server "${server}" error: ${message}`, isError: true, details: details({ ...extra, refused: true }) };
    };

    const client = this.client;
    if (client === undefined || client.connectionState !== "connected") {
      return fail("not connected", client === undefined ? "NOT_CONNECTED" : "TRANSPORT");
    }

    // Everything up to the request is synchronous, so a call's stamp commits to the influence and
    // run current when it was made, even with other calls in flight.
    const reply = session === "attested" ? this.reply : undefined;
    let params: Record<string, unknown> = { name: tool, arguments: args };
    // Attested connections only: the session, the run and when the call was stamped. Unsafe and off calls are plain.
    let attested: { reply: SessionReply; rid: string; stampedAt: number } | undefined;
    if (reply !== undefined) {
      const run = this.runs.current();
      if (run === undefined) {
        return fail("no active run: a tool call needs a user prompt first; nothing was sent", "NO_ACTIVE_RUN");
      }
      const rid = run.rid;
      const proof = toolCallProof(this.material.proofs, CLIENT_CHAIN, server, tool);
      if (proof === undefined) {
        return fail(`no policy proof for tool "${tool}"; nothing was sent`, "NO_PROOF", { rid });
      }
      try {
        const origin = this.runs.origin(reply.sess, this.material.sessionKey, INST);
        const influence = this.influence.entries();
        const stampedAt = this.now();
        const _meta = stampToolCall(
          { name: tool, args, callId },
          { origin, svc: PI_SVC, inst: INST, privateKey: this.material.piKey, ts: stampedAt, influence, proof, serverId: server },
        );
        params = { ...params, _meta };
        attested = { reply, rid, stampedAt };
      } catch (e) {
        return fail(`cannot stamp the call (${describeError(e).message}); nothing was sent`, "STAMP_FAILED", { rid });
      }
    }
    const withRid = attested !== undefined ? { rid: attested.rid } : {};
    if (attested !== undefined) {
      this.evidence.write({ v: 1, type: "call", server, tool, callId, rid: attested.rid, now: attested.stampedAt, params: params as EvidenceCallParams });
    }
    // `now` is the value passed to verifyResponse; without one (a refusal, a malformed result) the time is read here.
    const respond = (result: unknown, now?: number) => {
      if (attested !== undefined) {
        this.evidence.write({ v: 1, type: "response", server, tool, callId, rid: attested.rid, now: now ?? this.now(), result });
      }
    };
    this.events.emit({ type: "call", server, tool, callId, ...withRid, session });

    let raw: unknown;
    try {
      raw = await client.request("tools/call", params);
    } catch (e) {
      const d = describeError(e);
      return fail(d.message, d.code, withRid, d.rpcCode);
    }
    if (!isObject(raw)) {
      respond(raw);
      return fail("malformed tools/call result", "MALFORMED_RESULT", withRid);
    }

    const ctx: ResultContext =
      this.mode === "off"
        ? { session: "off" }
        : attested !== undefined
          ? { session: "attested", reply: attested.reply, svc: PI_SVC, rid: attested.rid, callId, allowedOrigins: SERVER_ORIGINS, nonces: this.responseNonces, now: () => this.now() }
          : { session: "unsafe" };
    const reading = readToolResult(raw, ctx);
    if (reading.kind === "refused") {
      respond(raw);
      // A refusal: the tool did not run. Its text is replaced by a local message, so no server content
      // reaches the model unrecorded, and nothing is recorded as influence.
      const out = details({ ...withRid, verdict: reading.verdict, refused: true });
      this.events.emit({ type: "response", server, tool, callId, ...withRid, verdict: reading.verdict, isError: true, classes: out.influence });
      return { text: refusalText(reading.verdict), isError: true, details: out };
    }
    // A result JCS cannot hash is an error: its text is dropped and nothing is recorded. Off mode hashes
    // nothing and passes such results through like a baseline client.
    if (reading.kind === "malformed") {
      respond(raw, reading.verifiedAt);
      return fail("malformed tools/call result", "MALFORMED_RESULT", withRid);
    }
    const found = reading.influence;
    if (found.kind === "labels") {
      this.influence.recordLabels(server, found.labels, found.hash);
    } else if (found.kind === "untrusted") {
      this.influence.recordUntrusted(`server:${server}`, found.hash);
    }
    respond(raw, reading.verifiedAt);
    const text = textOf(raw);
    const labels: InfluenceClass[] | undefined = found.kind === "labels" ? found.labels.map((l) => l.cls) : undefined;
    const isError = raw.isError === true;
    const extra = {
      ...withRid,
      ...(reading.verdict !== undefined ? { verdict: reading.verdict } : {}),
      ...(reading.verification !== undefined ? { verify: reading.verification } : {}),
      ...(labels !== undefined ? { labels } : {}),
    };
    const out = details(extra);
    this.events.emit({ type: "response", server, tool, callId, ...extra, isError, classes: out.influence });
    return { text, isError, details: out };
  }

  async close(): Promise<void> {
    const client = this.client;
    if (client !== undefined) {
      await client.close().catch(() => {});
    }
  }
}
