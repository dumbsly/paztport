// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { JSON_RPC_ERROR_CODES, McpClient, McpError, McpTimeoutError, StdioTransport, type Tool } from "@earendil-works/pi-mcp";
import {
  bindMcpCall,
  commitInfluence,
  decode,
  encode,
  META_CALL_ID,
  META_CHAIN,
  META_INFLUENCE,
  META_PROOF,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  randomBytes,
  SESSION_METHOD,
  signStampV2,
  verifyResponse,
  verifySessionReply,
  type InfluenceClass,
  type ReasonCode,
  type SessionReply,
  type SessionRequest,
} from "@paztport/path-attest";
import type { ExtensionMode, ServerSpec } from "./config.ts";
import type { EventLog } from "./events.ts";
import { EvidenceLog, type EvidenceRecord } from "./evidence.ts";
import { contentHash, type InfluenceStore } from "./influence.ts";
import { readPin, type ClientMaterial } from "./keys.ts";
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

/** Where a server refusal is carried on a tools/call result. */
const META_VERDICT = "paztport/verdict";
const INST = "pi-1";
const SAFE_CALL_ID = /^[A-Za-z0-9_-]{1,128}$/;
/**
 * Every refusal code the library defines (the mock server's verdicts are all ReasonCodes). A Record,
 * so tsc flags a code added to the library and missing here.
 */
const REFUSAL_CODES: Record<Exclude<ReasonCode, "OK">, true> = {
  CHAIN_MISSING: true,
  BAD_ORIGIN: true,
  BAD_SIGNATURE: true,
  BROKEN_LINK: true,
  EXPIRED: true,
  RID_MISMATCH: true,
  BINDING_MISMATCH: true,
  REPLAY: true,
  PATH_NOT_ALLOWED: true,
  SESSION_UNKNOWN: true,
  CLIENT_PATH_NOT_ALLOWED: true,
  INFLUENCE_MISMATCH: true,
  INFLUENCE_DENIED: true,
  UNSAFE_SESSION: true,
};
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

function isStringMap(v: unknown): v is Record<string, string> {
  return isObject(v) && Object.values(v).every((x) => typeof x === "string");
}

function isSignedRoot(v: unknown): boolean {
  return isObject(v) && typeof v.rootId === "string" && typeof v.root === "string" && typeof v.sig === "string";
}

function isSessionReply(v: unknown): v is SessionReply {
  return (
    isObject(v) &&
    (v.serverRoot === null || isSignedRoot(v.serverRoot)) &&
    typeof v.serverPolicyKey === "string" &&
    isStringMap(v.serverKeyring) &&
    typeof v.nonce === "string" &&
    typeof v.sess === "string" &&
    (v.status === "attested" || v.status === "unsafe") &&
    Array.isArray(v.disabled) &&
    v.disabled.every((d) => typeof d === "string") &&
    typeof v.sig === "string"
  );
}

/** The text items of a result's content, joined by newlines. */
function textOf(raw: Record<string, unknown>): string {
  const content = Array.isArray(raw.content) ? raw.content : [];
  return content
    .filter((c): c is { type: "text"; text: string } => isObject(c) && c.type === "text" && typeof c.text === "string")
    .map((c) => c.text)
    .join("\n");
}

/**
 * The paztport/verdict on a result, if any. The reason is server data that reaches the model, so
 * anything but a known refusal code becomes "UNKNOWN".
 */
function verdictOf(raw: Record<string, unknown>): { reason: string; audit: boolean } | undefined {
  const meta = raw._meta;
  if (!isObject(meta) || !Object.hasOwn(meta, META_VERDICT)) {
    return undefined;
  }
  const v = meta[META_VERDICT];
  const reason = isObject(v) && typeof v.reason === "string" && Object.hasOwn(REFUSAL_CODES, v.reason) ? v.reason : "UNKNOWN";
  return { reason, audit: isObject(v) && v.audit === true };
}

/**
 * The text the model gets for a refusal. An influence or session refusal says only that the action was
 * unsafe and stays blocked for the session, never why, and asks the model to stop and tell the user. The
 * wording only nudges; the call is refused whatever the model does next. Other codes are technical, not
 * sticky, and keep the plain message with the code.
 */
function refusalText(reason: string): string {
  if (reason === "INFLUENCE_DENIED" || reason === "UNSAFE_SESSION") {
    return (
      "Paztport stopped this action. The system flagged it as unsafe, and it was not carried out. Actions like it stay " +
      "blocked for the rest of this session, so retrying it or trying another way will not work. A stop like this is the " +
      "system doing what the user wants. It is not a fault on your part. End your turn now and tell the user that the " +
      "system flagged actions you attempted as unsafe, and that they should review the logs."
    );
  }
  return `Paztport refused this call: ${reason}`;
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
    const req: SessionRequest = {
      clientRoot: this.mode === "no-root" ? null : this.material.signedRoot,
      clientPolicyKey: this.material.policyPublicKey,
      clientKeyring: this.material.keyring,
      nonce: newNonce(),
    };
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
    let reply: unknown;
    let failure = "MALFORMED_REPLY";
    try {
      reply = await client.request(SESSION_METHOD, req as unknown as Record<string, unknown>);
    } catch (e) {
      if (e instanceof McpError && e.code === JSON_RPC_ERROR_CODES.methodNotFound) {
        record(req, null, "unsafe", "METHOD_NOT_FOUND");
        return unsafe("METHOD_NOT_FOUND"); // no Paztport on the server, so no session to replace
      }
      failure = "HANDSHAKE_ERROR";
    }
    if (failure !== "HANDSHAKE_ERROR" && isSessionReply(reply)) {
      failure = reply.serverPolicyKey !== pin ? "PIN_MISMATCH" : !verifySessionReply(reply, req, pin) ? "BAD_SIGNATURE" : "";
    }
    if (failure !== "" || !isSessionReply(reply)) {
      // The server may now hold an attested session that this client cannot use: every unstamped call
      // would be refused. This holds after a timeout or a transport error too, since the server may
      // have opened the session before the reply was lost. Replace it, best effort, with an unsafe one
      // (no client root) so reads work and writes are refused UNSAFE_SESSION. The second reply is not
      // trusted either way.
      record(req, reply, "unsafe", failure);
      const replacement: SessionRequest = { ...req, clientRoot: null, nonce: newNonce() };
      let second: unknown;
      try {
        second = await client.request(SESSION_METHOD, replacement as unknown as Record<string, unknown>);
      } catch {
        // stays unsafe
      }
      record(replacement, second, "unsafe", failure);
      return unsafe(failure);
    }
    this.reply = reply;
    this.state = reply.status;
    if (reply.status === "unsafe") {
      this.reason = "UNSAFE";
    }
    record(req, reply, reply.status, this.reason);
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
    const reply = this.reply;
    let rid: string | undefined;
    let params: Record<string, unknown> = { name: tool, arguments: args };
    let stampedAt: number | undefined;
    if (session === "attested" && reply !== undefined) {
      const run = this.runs.current();
      if (run === undefined) {
        return fail("no active run: a tool call needs a user prompt first; nothing was sent", "NO_ACTIVE_RUN");
      }
      rid = run.rid;
      const route = `session/pi/mcp:${server}.${tool}`;
      const proof = Object.hasOwn(this.material.proofs, route) ? this.material.proofs[route] : undefined;
      if (proof === undefined) {
        return fail(`no policy proof for tool "${tool}"; nothing was sent`, "NO_PROOF", { rid });
      }
      try {
        const origin = this.runs.origin(reply.sess, this.material.sessionKey, INST);
        const infl = this.influence.entries();
        stampedAt = this.now();
        const pi = signStampV2(
          { svc: "pi", inst: INST, rid, ts: stampedAt, sess: reply.sess, bind: bindMcpCall(tool, callId, args), infl: commitInfluence(infl), prev: origin.sig },
          this.material.piKey,
        );
        params = {
          ...params,
          _meta: { [META_CHAIN]: [origin, pi], [META_PROOF]: proof, [META_INFLUENCE]: infl, [META_CALL_ID]: callId },
        };
      } catch (e) {
        return fail(`cannot stamp the call (${describeError(e).message}); nothing was sent`, "STAMP_FAILED", { rid });
      }
    }
    const withRid = rid !== undefined ? { rid } : {};
    // Attested connections only: what was sent, and when it was stamped. Unsafe and off calls are plain.
    const attested = session === "attested" && reply !== undefined && rid !== undefined && stampedAt !== undefined ? { rid, stampedAt } : undefined;
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

    const verdict = verdictOf(raw);
    if (verdict !== undefined && !verdict.audit) {
      respond(raw);
      // A refusal: the tool did not run. Its text is replaced by a local message, so no server content
      // reaches the model unrecorded, and nothing is recorded as influence.
      const out = details({ ...withRid, verdict: verdict.reason, refused: true });
      this.events.emit({ type: "response", server, tool, callId, ...withRid, verdict: verdict.reason, isError: true, classes: out.influence });
      return { text: refusalText(verdict.reason), isError: true, details: out };
    }

    // Hashing and verification can throw on results JSON allows but JCS rejects (a lone surrogate, a
    // number that parsed to Infinity). Such a result is an error, its text is dropped and nothing is
    // recorded: every throwing step runs before the first record. Off mode records nothing, so it
    // hashes nothing and passes such results through like a baseline client.
    const text = textOf(raw);
    let verify: string | undefined;
    let labels: InfluenceClass[] | undefined;
    let verifiedAt: number | undefined;
    if (this.mode !== "off") {
      try {
        const h = contentHash(raw);
        if (session === "attested" && reply !== undefined && rid !== undefined && reply.serverRoot !== null) {
          verifiedAt = this.now();
          const v = verifyResponse(raw, { rid, toolCallId: callId }, {
            keyring: reply.serverKeyring,
            root: decode(reply.serverRoot.root),
            rootId: reply.serverRoot.rootId,
            allowedOrigins: ["mcp-entry"],
            sess: reply.sess,
            nonces: this.responseNonces,
            now: verifiedAt,
          });
          verify = v.result.reason;
          if (v.result.ok) {
            labels = v.labels.map((l) => l.cls);
            this.influence.recordLabels(server, v.labels, h);
          } else {
            this.influence.recordUntrusted(`server:${server}`, h);
          }
        } else {
          this.influence.recordUntrusted(`server:${server}`, h);
        }
      } catch {
        respond(raw, verifiedAt);
        return fail("malformed tools/call result", "MALFORMED_RESULT", withRid);
      }
    }
    respond(raw, verifiedAt);
    const isError = raw.isError === true;
    const extra = {
      ...withRid,
      ...(verdict !== undefined ? { verdict: verdict.reason } : {}),
      ...(verify !== undefined ? { verify } : {}),
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
