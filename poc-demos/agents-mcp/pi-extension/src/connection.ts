// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { JSON_RPC_ERROR_CODES, McpClient, McpError, McpTimeoutError, StdioTransport, type Tool } from "@earendil-works/pi-mcp";
import {
  callsAfter,
  encode,
  extensionSettings,
  influenceBlock,
  NonceCache,
  NONCE_TTL_MS,
  randomBytes,
  requirement,
  sessionRequest,
  type ExtensionSettings,
  type InfluenceClass,
  type Requirement,
  type SessionReply,
} from "@paztport/core";
import {
  openSession,
  readToolResult,
  SESSION_METHOD,
  stampToolCall,
  toolCallProof,
  type ResultContext,
} from "@paztport/mcp";
import type { ExtensionMode, ServerSpec } from "./config.ts";
import type { EventLog } from "./events.ts";
import { EVIDENCE_VERSION, EvidenceLog, type EvidenceRecord } from "./evidence.ts";
import type { InfluenceStore } from "./influence.ts";
import { CLIENT_CHAIN, PI_SVC, readPin, type ClientMaterial } from "./keys.ts";
import { refusalText } from "./refusals.ts";
import { ORIGIN_BLOCK, type RunState } from "./runs.ts";

type EvidenceCallParams = Extract<EvidenceRecord, { type: "call" }>["params"];

/**
 * What a connection's handshake left it with: `attested` and `unsafe` as the server answered, `no-calls` when the
 * client's requirement of the server lets it make no call in the session it got, and `off` when Paztport is off.
 */
export type SessionState = "attested" | "unsafe" | "no-calls" | "off";

/** The extensions this client acts on and carries: `influence`. */
export const CLIENT_EXTENSIONS: ExtensionSettings = extensionSettings(["influence"]);

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
    /**
     * The classes of the entries the result added to the session's influence, in order (the reading's `entries`):
     * one for each label of a response that verified, otherwise `local-untrusted`. Absent when the reading gives no
     * entries: a refusal, a local error, off mode, or a client that does not act on `influence`.
     */
    added?: InfluenceClass[];
    /**
     * Set when the server's response required an extension this client does not act on (check 9c): its text was
     * withheld and the call failed, but the tool ran, so the outcome is not `refused`.
     */
    withheld?: true;
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
/** The server's entry service, from this client's own configuration: its responses start there, and its reply certificate names it. */
const SERVER_ENTRY = "mcp-entry";
/** The server hop a verified response must start at. */
const SERVER_ORIGINS = [SERVER_ENTRY];
/** What the model is told for a withheld result; it holds nothing of the result. */
const WITHHELD_MESSAGE =
  "the server's response requires an extension this client does not act on; its result was withheld, " +
  "and the call is not retried";
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
 * One MCP server over stdio. In an attested session every tools/call carries the prompt-origin chain, the route proof
 * and the blocks: the origin's, and pi's with the influence the call was made under and what the session requires of
 * the server. Every result's reading gives what it adds to the influence. Unsafe and off sessions send plain calls; a
 * no-calls session sends none.
 */
export class ServerConnection {
  private readonly spec: ServerSpec;
  private readonly mode: ExtensionMode;
  private readonly material: ClientMaterial;
  private readonly influence: InfluenceStore;
  private readonly runs: RunState;
  private readonly events: EventLog;
  private readonly evidence: EvidenceLog;
  private readonly extensions: ExtensionSettings;
  /** What this client requires of the server, from its configuration; it applies in every mode but off. */
  private readonly requirement: Requirement;
  private readonly now: () => number;
  private readonly responseNonces = new NonceCache(NONCE_TTL_MS);
  private client: McpClient | undefined;
  private transport: StdioTransport | undefined;
  private reply: SessionReply | undefined;
  private state: SessionState = "unsafe";
  private reason: string | undefined = "NOT_CONNECTED";
  /** What each call's block requires of the server: the attested session's `requires`. */
  private requires: string[] = [];
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
    extensions: ExtensionSettings = CLIENT_EXTENSIONS,
  ) {
    this.spec = spec;
    this.mode = mode;
    this.material = material;
    this.influence = influence;
    this.runs = runs;
    this.events = events;
    this.now = now;
    this.evidence = evidence;
    this.extensions = extensions;
    this.requirement = requirement(spec.requires ?? [], spec.continueWithoutRequired ?? false);
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
    // No handshake is sent: the session is unsafe, and under a requirement without its switch the client makes no call
    // in it (callsAfter, as for an unsafe reply).
    const unsafe = (reason: string) => {
      this.state = callsAfter("UNSAFE", [], this.requirement).calls ? "unsafe" : "no-calls";
      this.reason = reason;
    };
    this.reason = undefined;
    this.requires = [];
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
      keyringNotAfter: this.material.keyringNotAfter,
    });
    // Each request that was sent is written to the evidence file as it happens, as its token with the reply token
    // (null when there was none) and the state it left this connection in. A replacement is sent only after a first
    // exchange that was not attested, so it is never attested either.
    const opened = await openSession({
      request: req,
      pin,
      serverEntry: SERVER_ENTRY,
      now: () => this.now(),
      send: (params) => client.request(SESSION_METHOD, params),
      rpcCode: (e) => (e instanceof McpError ? e.code : undefined),
      requirement: this.requirement,
      onExchange: (x, first) =>
        this.evidence.write({
          v: EVIDENCE_VERSION,
          type: "session",
          server: this.spec.id,
          request: x.request,
          reply: x.reply,
          pin,
          status: first.status,
          ...(first.status !== "attested" ? { reason: first.reason } : {}),
        }),
    });
    const { outcome } = opened;
    if (outcome.status === "attested") {
      this.reply = outcome.reply;
      this.requires = outcome.requires;
      this.state = "attested";
      return;
    }
    this.state = outcome.status;
    this.reason = outcome.reason;
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
    // `event` adds codes to the error event: the JSON-RPC code, or the reason of a no-calls session.
    const fail = (
      message: string,
      code: string,
      extra: Partial<CallOutcome["details"]> = {},
      event: { rpcCode?: number; reason?: string } = {},
    ): CallOutcome => {
      this.events.emit({
        type: "error",
        server,
        tool,
        callId,
        ...(extra.rid !== undefined ? { rid: extra.rid } : {}),
        code,
        ...event,
      });
      return { text: `MCP server "${server}" error: ${message}`, isError: true, details: details({ ...extra, refused: true }) };
    };

    if (session === "no-calls") {
      const reason = this.reason ?? "UNKNOWN";
      const message = `no attested session gives what this client requires of the server (${reason}); nothing was sent`;
      return fail(message, "NO_CALLS", {}, { reason });
    }
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
        // pi's block: every entry the session holds, and what the session requires of the server
        const block = influenceBlock(this.influence.entries(), this.requires);
        const stampedAt = this.now();
        const _meta = stampToolCall(
          { name: tool, args, callId },
          {
            origin,
            originBlock: ORIGIN_BLOCK,
            svc: PI_SVC,
            inst: INST,
            privateKey: this.material.piKey,
            ts: stampedAt,
            block,
            requires: this.requires,
            proof,
            serverId: server,
          },
        );
        params = { ...params, _meta };
        attested = { reply, rid, stampedAt };
      } catch (e) {
        return fail(`cannot stamp the call (${describeError(e).message}); nothing was sent`, "STAMP_FAILED", { rid });
      }
    }
    const withRid = attested !== undefined ? { rid: attested.rid } : {};
    if (attested !== undefined) {
      this.evidence.write({
        v: EVIDENCE_VERSION,
        type: "call",
        server,
        tool,
        callId,
        rid: attested.rid,
        now: attested.stampedAt,
        params: params as EvidenceCallParams,
      });
    }
    // `now` is the time the reading verified the response at; without one (a refusal, a malformed result) it is read
    // here.
    const respond = (result: unknown, now?: number) => {
      if (attested !== undefined) {
        const at = now ?? this.now();
        this.evidence.write({ v: EVIDENCE_VERSION, type: "response", server, tool, callId, rid: attested.rid, now: at, result });
      }
    };
    this.events.emit({ type: "call", server, tool, callId, ...withRid, session });

    let raw: unknown;
    try {
      raw = await client.request("tools/call", params);
    } catch (e) {
      const d = describeError(e);
      return fail(d.message, d.code, withRid, d.rpcCode !== undefined ? { rpcCode: d.rpcCode } : {});
    }
    if (!isObject(raw)) {
      respond(raw);
      return fail("malformed tools/call result", "MALFORMED_RESULT", withRid);
    }

    const ctx: ResultContext =
      this.mode === "off"
        ? { session: "off" }
        : attested !== undefined
          ? {
              session: "attested",
              serverId: server,
              reply: attested.reply,
              svc: PI_SVC,
              rid: attested.rid,
              callId,
              allowedOrigins: SERVER_ORIGINS,
              nonces: this.responseNonces,
              now: () => this.now(),
              extensions: this.extensions,
            }
          : { session: "unsafe", serverId: server, extensions: this.extensions };
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
    // What the result adds is the reading's, for a withheld result as for one that is read: no entry is built here.
    const found = reading.influence;
    if (found.kind === "entries") {
      this.influence.add(found.entries);
    }
    const added = found.kind === "entries" ? { added: found.entries.map((e) => e.cls) } : {};
    respond(raw, reading.verifiedAt);
    if (reading.kind === "withheld") {
      // The tool ran, so the call is not retried; nothing of the result reaches the model or the events log.
      const extra = { ...withRid, verify: reading.reason, ...added, withheld: true as const };
      const out = details(extra);
      this.events.emit({ type: "response", server, tool, callId, ...extra, isError: true, classes: out.influence });
      return { text: `MCP server "${server}" error: ${WITHHELD_MESSAGE}`, isError: true, details: out };
    }
    const text = textOf(raw);
    const isError = raw.isError === true;
    const extra = {
      ...withRid,
      ...(reading.verdict !== undefined ? { verdict: reading.verdict } : {}),
      ...(reading.verification !== undefined ? { verify: reading.verification } : {}),
      ...added,
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
