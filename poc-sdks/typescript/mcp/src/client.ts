// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindResult,
  checkSessionReply,
  commitInfluence,
  decode,
  readSessionReply,
  replacementRequest,
  routeOf,
  sanitiseVerdictReason,
  serverPolicyNotAfter,
  signStamp,
  writeToken,
  type ContentLabel,
  type InfluenceEntry,
  type MerkleProof,
  type NonceCache,
  type SessionReply,
  type SessionRequest,
  type Stamp,
} from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF, META_VERDICT } from "./meta.ts";
import { verifyMcpResponse } from "./response.ts";
import { readVerdict, type Verdict } from "./verdict.ts";
import { mcpReceiver } from "./verify-call.ts";

/** The JSON-RPC error code for an unknown method: a server without Paztport answers paztport/session with it. */
const METHOD_NOT_FOUND = -32601;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * What a handshake left the client with. `replaceSession` is set when the server may now hold an
 * attested session that this client cannot use, so every unstamped call would be refused. That holds
 * after a timeout or a transport error too, since the server may have opened the session before the
 * reply was lost. The client then replaces it, best effort, with `replacementRequest`.
 */
export type SessionOutcome =
  | { status: "attested"; reply: SessionReply }
  | { status: "unsafe"; reason: string; replaceSession: boolean };

const unusable = (reason: string): SessionOutcome => ({ status: "unsafe", reason, replaceSession: true });

/**
 * The reply token a paztport/session result carries: the result holds exactly `reply`, a string, plus an optional
 * `_meta`, which MCP allows on every result. Undefined for any other result, which a client takes as MALFORMED_REPLY.
 */
export function sessionReplyToken(result: unknown): string | undefined {
  if (!isObject(result) || !Object.hasOwn(result, "reply") || typeof result.reply !== "string") {
    return undefined;
  }
  return Object.keys(result).every((name) => name === "reply" || name === "_meta") ? result.reply : undefined;
}

/**
 * Classifies a paztport/session result against the request it answers, the pinned server policy key, the server's
 * entry service from the client's own configuration, and the time `now` (ms): a result other than a reply token
 * (sessionReplyToken) is MALFORMED_REPLY, and the token is checked by checkSessionReply.
 */
export function classifySessionReply(result: unknown, req: SessionRequest, pin: string, serverEntry: string, now: number): SessionOutcome {
  const token = sessionReplyToken(result);
  if (token === undefined) {
    return unusable("MALFORMED_REPLY");
  }
  const check = checkSessionReply(token, req, pin, serverEntry, now);
  if (check === "ATTESTED") {
    return { status: "attested", reply: readSessionReply(token) };
  }
  return check === "UNSAFE" ? { status: "unsafe", reason: "UNSAFE", replaceSession: false } : unusable(check);
}

/**
 * Classifies a paztport/session request that failed: a JSON-RPC error with `rpcCode`, or none for a
 * timeout or transport error. Method not found means the server has no Paztport, so no session to replace.
 */
export function classifySessionError(rpcCode: number | undefined): SessionOutcome {
  return rpcCode === METHOD_NOT_FOUND ? { status: "unsafe", reason: "METHOD_NOT_FOUND", replaceSession: false } : unusable("HANDSHAKE_ERROR");
}

/**
 * A request sent in the handshake, as its token, and the `reply` of the result that answered it: null when there was
 * no result, or its `reply` is not a string.
 */
export type SessionExchange = { request: string; reply: string | null };

/** What `openSession` did: the outcome, and each exchange, in order, so the caller can keep evidence. */
export type OpenedSession = { outcome: SessionOutcome; exchanges: SessionExchange[] };

/** A result's `reply` when it is a string, else null: what an exchange records of the result. */
function replyOf(result: unknown): string | null {
  return isObject(result) && typeof result.reply === "string" ? result.reply : null;
}

/**
 * Opens a session: sends the params `{request}`, the request's token, through `send`, which rejects on a JSON-RPC
 * error, a timeout or a transport error (`rpcCode` gives the JSON-RPC code of what it rejected with, if any), and
 * classifies the result. When the outcome warrants a replacement, sends `replacementRequest` (a null root, so the
 * server cannot attest it) best effort; the session is unsafe whatever comes back, and the outcome is the first one's.
 * `onExchange` reports each exchange as it happens, so a caller keeping evidence loses nothing if the replacement
 * hangs. Throws if the request cannot be written.
 */
export async function openSession(opts: {
  request: SessionRequest;
  pin: string;
  serverEntry: string;
  now: () => number;
  send: (params: { request: string }) => Promise<unknown>;
  rpcCode: (error: unknown) => number | undefined;
  /** Called with each exchange as it happens, with the outcome the first reply gave, before any replacement is sent. */
  onExchange?: (exchange: SessionExchange, outcome: SessionOutcome) => void;
}): Promise<OpenedSession> {
  const { request, send } = opts;
  const token = writeToken(request);
  let result: unknown = null;
  let outcome: SessionOutcome | undefined;
  try {
    result = await send({ request: token });
  } catch (e) {
    outcome = classifySessionError(opts.rpcCode(e));
  }
  outcome ??= classifySessionReply(result, request, opts.pin, opts.serverEntry, opts.now());
  const exchanges: SessionExchange[] = [{ request: token, reply: replyOf(result) }];
  opts.onExchange?.(exchanges[0]!, outcome);
  if (outcome.status === "unsafe" && outcome.replaceSession) {
    const replacement = writeToken(replacementRequest(request));
    let second: unknown = null;
    try {
      second = await send({ request: replacement });
    } catch {
      // stays unsafe
    }
    exchanges.push({ request: replacement, reply: replyOf(second) });
    opts.onExchange?.(exchanges[1]!, outcome);
  }
  return { outcome, exchanges };
}

/**
 * The client's proof for the route a tools/call takes: the services of its chain, then
 * `mcp:<serverId>.<tool>`. Own keys only, so a tool named like an Object.prototype member has none.
 */
export function toolCallProof(
  proofs: Record<string, MerkleProof>,
  chainSvcs: readonly string[],
  serverId: string,
  tool: string,
): MerkleProof | undefined {
  const route = routeOf([...chainSvcs, mcpReceiver(serverId, tool)]);
  return Object.hasOwn(proofs, route) ? proofs[route] : undefined;
}

/** What the calling hop signs a tools/call with. */
export type ToolCallStamp = {
  /** The run's origin stamp for this session, naming `svc` as its receiver; the call's stamp continues its rid, session and chain. */
  origin: Stamp;
  svc: string;
  inst: string;
  privateKey: string;
  ts: number;
  /** The influence the call is made under. */
  influence: InfluenceEntry[];
  proof: MerkleProof;
  /** The server the call goes to: the call's stamp names `mcp:<serverId>.<tool>` as its receiver. */
  serverId: string;
};

/**
 * The `_meta` for an attested tools/call: the tokens of the chain (the origin and a v3 stamp by the calling hop over
 * the call's receiver, binding and influence), of the route proof and of the influence, and the call id. Throws if a
 * stamp cannot be signed or a token written.
 */
export function stampToolCall(call: { name: string; args: unknown; callId: string }, s: ToolCallStamp): Record<string, string> {
  const hop = signStamp(
    {
      svc: s.svc,
      inst: s.inst,
      rid: s.origin.rid,
      ts: s.ts,
      sess: s.origin.sess,
      rcv: mcpReceiver(s.serverId, call.name),
      bind: bindMcpCall(call.name, call.callId, call.args),
      infl: commitInfluence(s.influence),
      prev: s.origin.sig,
    },
    s.privateKey,
  );
  return {
    [META_CHAIN]: writeToken([s.origin, hop]),
    [META_PROOF]: writeToken(s.proof),
    [META_INFLUENCE]: writeToken(s.influence),
    [META_CALL_ID]: call.callId,
  };
}

/**
 * The paztport/verdict on a result, if any. The reason is server data that reaches the model, so
 * anything but a known refusal code becomes "UNKNOWN", and so does a verdict that is not a token that reads, which is
 * then a refusal. An unsigned refusal is still honoured: it only denies service, so a forged one can withhold a result
 * but never add influence.
 */
function verdictOf(raw: Record<string, unknown>): { reason: string; audit: boolean } | undefined {
  const meta = raw._meta;
  if (!isObject(meta) || !Object.hasOwn(meta, META_VERDICT)) {
    return undefined;
  }
  const token = meta[META_VERDICT];
  let verdict: Verdict | undefined;
  try {
    verdict = typeof token === "string" ? readVerdict(token) : undefined;
  } catch {
    verdict = undefined;
  }
  return verdict === undefined ? { reason: "UNKNOWN", audit: false } : { reason: sanitiseVerdictReason(verdict.reason), audit: verdict.audit === true };
}

/** What a result adds to the client's influence: its verified labels, untrusted content, or nothing. */
export type ResultInfluence =
  | { kind: "labels"; labels: ContentLabel[]; hash: string }
  | { kind: "untrusted"; hash: string }
  | { kind: "none" };

/**
 * The session a result arrived in. Off records nothing, so it hashes nothing. An attested call's
 * response is verified against the server's root and keyring, and must end at `svc`, the client's own
 * service that made the call; `now` is read only when it is.
 */
export type ResultContext =
  | { session: "off" }
  | { session: "unsafe" }
  | {
      session: "attested";
      reply: SessionReply;
      svc: string;
      rid: string;
      callId: string;
      allowedOrigins: string[];
      nonces: NonceCache;
      now: () => number;
    };

/**
 * How a tools/call result reads. A refusal (a non-audit verdict) means the tool did not run, and
 * nothing of it is recorded. A malformed result is one JCS cannot hash (a lone surrogate, a number
 * that parsed to Infinity); nothing of it is recorded either. `verifiedAt` is the time verification used.
 */
export type ToolResultReading =
  | { kind: "refused"; verdict: string; influence: { kind: "none" } }
  | { kind: "malformed"; verifiedAt?: number }
  | { kind: "read"; verdict?: string; verification?: string; verifiedAt?: number; influence: ResultInfluence };

/** Reads a tools/call result: its verdict, its verification and what it adds to influence. Never throws. */
export function readToolResult(raw: Record<string, unknown>, ctx: ResultContext): ToolResultReading {
  const verdict = verdictOf(raw);
  if (verdict !== undefined && !verdict.audit) {
    return { kind: "refused", verdict: verdict.reason, influence: { kind: "none" } };
  }
  const withVerdict = verdict !== undefined ? { verdict: verdict.reason } : {};
  if (ctx.session === "off") {
    return { kind: "read", ...withVerdict, influence: { kind: "none" } };
  }
  let verifiedAt: number | undefined;
  try {
    const hash = bindResult(raw);
    if (ctx.session === "attested" && ctx.reply.serverRoot !== null) {
      verifiedAt = ctx.now();
      const v = verifyMcpResponse(raw, { rid: ctx.rid, toolCallId: ctx.callId, receiver: ctx.svc }, {
        keyring: ctx.reply.serverKeyring,
        root: decode(ctx.reply.serverRoot.root),
        rootId: ctx.reply.serverRoot.rootId,
        allowedOrigins: ctx.allowedOrigins,
        sess: ctx.reply.sess,
        nonces: ctx.nonces,
        now: verifiedAt,
        policyNotAfter: serverPolicyNotAfter(ctx.reply),
      });
      const influence: ResultInfluence = v.result.ok ? { kind: "labels", labels: v.labels, hash } : { kind: "untrusted", hash };
      return { kind: "read", ...withVerdict, verification: v.result.reason, verifiedAt, influence };
    }
    return { kind: "read", ...withVerdict, influence: { kind: "untrusted", hash } };
  } catch {
    return { kind: "malformed", ...(verifiedAt !== undefined ? { verifiedAt } : {}) };
  }
}
