// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindResult,
  checkSessionReply,
  commitInfluence,
  decode,
  routeOf,
  sanitiseVerdictReason,
  serverPolicyNotAfter,
  signStampV3,
  type ContentLabel,
  type InfluenceEntry,
  type MerkleProof,
  type NonceCache,
  type SessionReply,
  type SessionRequest,
  type StampV3,
} from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF, META_VERDICT } from "./meta.ts";
import { verifyMcpResponse } from "./response.ts";
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
 * Classifies a paztport/session reply against the request it answers, the pinned server policy key, the server's
 * entry service from the client's own configuration, and the time `now` (ms).
 */
export function classifySessionReply(raw: unknown, req: SessionRequest, pin: string, serverEntry: string, now: number): SessionOutcome {
  const check = checkSessionReply(raw, req, pin, serverEntry, now);
  if (check === "ATTESTED") {
    return { status: "attested", reply: raw as SessionReply };
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
  origin: StampV3;
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
 * The `_meta` for an attested tools/call: the origin and a v3 stamp by the calling hop over the call's
 * receiver, binding and influence, the route proof, the influence and the call id. Throws if a stamp cannot be signed.
 */
export function stampToolCall(call: { name: string; args: unknown; callId: string }, s: ToolCallStamp): Record<string, unknown> {
  const hop = signStampV3(
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
  return { [META_CHAIN]: [s.origin, hop], [META_PROOF]: s.proof, [META_INFLUENCE]: s.influence, [META_CALL_ID]: call.callId };
}

/**
 * The paztport/verdict on a result, if any. The reason is server data that reaches the model, so
 * anything but a known refusal code becomes "UNKNOWN". An unsigned refusal is still honoured: it only
 * denies service, so a forged one can withhold a result but never add influence.
 */
function verdictOf(raw: Record<string, unknown>): { reason: string; audit: boolean } | undefined {
  const meta = raw._meta;
  if (!isObject(meta) || !Object.hasOwn(meta, META_VERDICT)) {
    return undefined;
  }
  const v = meta[META_VERDICT];
  const reason = sanitiseVerdictReason(isObject(v) ? v.reason : undefined);
  return { reason, audit: isObject(v) && v.audit === true };
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
