// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindResult,
  callsAfter,
  checkSessionReply,
  commitBlock,
  decode,
  INFLUENCE,
  NO_REQUIREMENT,
  responseLabels,
  readSessionReply,
  replacementRequest,
  requireStampableNames,
  routeOf,
  sanitiseVerdictReason,
  serverPolicyNotAfter,
  signStamp,
  writeToken,
  type Block,
  type ContentLabel,
  type ExtensionSettings,
  type JsonValue,
  type MerkleProof,
  type NonceCache,
  type ReplyCheck,
  type Requirement,
  type SessionReply,
  type SessionRequest,
  type Stamp,
} from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_EXTENSIONS, META_PROOF, META_VERDICT } from "./meta.ts";
import { verifyMcpResponse } from "./response.ts";
import { readVerdict, type Verdict } from "./verdict.ts";
import { mcpReceiver } from "./verify-call.ts";

/** The JSON-RPC error code for an unknown method: a server without Paztport answers paztport/session with it. */
const METHOD_NOT_FOUND = -32601;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * What a handshake left the client with. An attested session carries `requires`, what each call's block requires of
 * this server. `no-calls` is a session in which the client's requirement lets it make no call (spec sessions.md, A
 * client that requires extensions); `unsafe` is one it calls in unattested. `replaceSession` is set when the server
 * may now hold an attested session that this client cannot use, so every unstamped call would be refused. That holds
 * after a timeout or a transport error too, since the server may have opened the session before the reply was lost.
 * The client then replaces it, best effort, with `replacementRequest`, whether or not it makes calls afterwards.
 */
export type SessionOutcome =
  | { status: "attested"; reply: SessionReply; requires: string[] }
  | { status: "unsafe"; reason: string; replaceSession: boolean }
  | { status: "no-calls"; reason: string; replaceSession: boolean };

/**
 * The outcome of a handshake whose first reply's check was `check`, null for a JSON-RPC error or a timeout, given as
 * `reason`, under `requirement`; `reply` is that reply when it read. What the client may do is callsAfter's. The
 * replacement follows the outcome as it would with no requirement, except after EXTENSION_REQUIRED: the reply was
 * sound, and the replacement would only open an unsafe session with a server known not to act on the extension.
 */
function outcomeOf(
  check: ReplyCheck | null,
  reason: string,
  reply: SessionReply | undefined,
  requirement: Requirement,
): SessionOutcome {
  const after = callsAfter(check, reply?.extensions ?? [], requirement);
  // An attested reply is never replaced, nor a sound one (UNSAFE, EXTENSION_REQUIRED), nor a server with no Paztport.
  const replaceSession = check === null
    ? reason !== "METHOD_NOT_FOUND"
    : check !== "ATTESTED" && check !== "UNSAFE" && check !== "EXTENSION_REQUIRED";
  if (!after.calls) {
    return { status: "no-calls", reason, replaceSession };
  }
  if (reply !== undefined && (check === "ATTESTED" || check === "EXTENSION_REQUIRED")) {
    return { status: "attested", reply, requires: after.requires };
  }
  return { status: "unsafe", reason, replaceSession };
}

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
 * entry service from the client's own configuration, the time `now` (ms), and what the client requires of the server
 * (none by default): a result other than a reply token (sessionReplyToken) is MALFORMED_REPLY, and the token is
 * checked by checkSessionReply with the requirement's names.
 */
export function classifySessionReply(
  result: unknown,
  req: SessionRequest,
  pin: string,
  serverEntry: string,
  now: number,
  requirement: Requirement = NO_REQUIREMENT,
): SessionOutcome {
  const token = sessionReplyToken(result);
  const check = token === undefined
    ? "MALFORMED_REPLY"
    : checkSessionReply(token, req, pin, serverEntry, now, requirement.extensions);
  // Every outcome but MALFORMED_REPLY has read the reply, so this read does not throw.
  const reply = token === undefined || check === "MALFORMED_REPLY" ? undefined : readSessionReply(token);
  return outcomeOf(check, check, reply, requirement);
}

/**
 * Classifies a paztport/session request that failed: a JSON-RPC error with `rpcCode`, or none for a timeout or
 * transport error, under what the client requires of the server (none by default). Method not found means the server
 * has no Paztport, so no session to replace.
 */
export function classifySessionError(
  rpcCode: number | undefined,
  requirement: Requirement = NO_REQUIREMENT,
): SessionOutcome {
  return outcomeOf(null, rpcCode === METHOD_NOT_FOUND ? "METHOD_NOT_FOUND" : "HANDSHAKE_ERROR", undefined, requirement);
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
 * classifies the result under `requirement` (none by default). When the outcome warrants a replacement, sends
 * `replacementRequest` (a null root, so the server cannot attest it) best effort, whether or not the requirement lets
 * the client make calls; the session is unsafe whatever comes back, and the outcome is the first one's. `onExchange`
 * reports each exchange as it happens, so a caller keeping evidence loses nothing if the replacement hangs. Throws if
 * the request cannot be written.
 */
export async function openSession(opts: {
  request: SessionRequest;
  pin: string;
  serverEntry: string;
  now: () => number;
  send: (params: { request: string }) => Promise<unknown>;
  rpcCode: (error: unknown) => number | undefined;
  /** What the client requires of this server; none when omitted. */
  requirement?: Requirement;
  /** Called with each exchange as it happens, with the outcome the first reply gave, before any replacement is sent. */
  onExchange?: (exchange: SessionExchange, outcome: SessionOutcome) => void;
}): Promise<OpenedSession> {
  const { request, send } = opts;
  const requirement = opts.requirement ?? NO_REQUIREMENT;
  const token = writeToken(request);
  let result: unknown = null;
  let outcome: SessionOutcome | undefined;
  try {
    result = await send({ request: token });
  } catch (e) {
    outcome = classifySessionError(opts.rpcCode(e), requirement);
  }
  outcome ??= classifySessionReply(result, request, opts.pin, opts.serverEntry, opts.now(), requirement);
  const exchanges: SessionExchange[] = [{ request: token, reply: replyOf(result) }];
  opts.onExchange?.(exchanges[0]!, outcome);
  if (outcome.status !== "attested" && outcome.replaceSession) {
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
  /** The block the origin stamp commits to, sent as it is. */
  originBlock: Block;
  svc: string;
  inst: string;
  privateKey: string;
  ts: number;
  /** The calling hop's own block: its items for this request so far, and what it requires of this server. */
  block: Block;
  proof: MerkleProof;
  /** The server the call goes to: the call's stamp names `mcp:<serverId>.<tool>` as its receiver. */
  serverId: string;
};

/**
 * The `_meta` for an attested tools/call: the tokens of the chain (the origin and a stamp by the calling hop over the
 * call's receiver, binding and block), of the route proof and of the blocks, `[originBlock, block]`, and the call id.
 * The blocks travel also when both are empty, so this SDK sends one form. Throws if a stamp cannot be signed or a
 * token written, if `svc` or the receiver (`mcp:<server>.<tool>`) is not a route node, or if `originBlock` is not the
 * block the origin's `ext` commits to.
 */
export function stampToolCall(call: { name: string; args: unknown; callId: string }, s: ToolCallStamp): Record<string, string> {
  const rcv = mcpReceiver(s.serverId, call.name);
  requireStampableNames(s.svc, rcv);
  // Fails here rather than as EXTENSION_MISMATCH at the server, with nothing said locally.
  if (commitBlock(s.originBlock) !== s.origin.ext) {
    throw new Error("originBlock is not the block the origin stamp commits to");
  }
  const hop = signStamp(
    {
      svc: s.svc,
      inst: s.inst,
      rid: s.origin.rid,
      ts: s.ts,
      sess: s.origin.sess,
      rcv,
      bind: bindMcpCall(call.name, call.callId, call.args),
      ext: commitBlock(s.block),
      prev: s.origin.sig,
    },
    s.privateKey,
  );
  return {
    [META_CHAIN]: writeToken([s.origin, hop]),
    [META_PROOF]: writeToken(s.proof),
    [META_EXTENSIONS]: writeToken([s.originBlock, s.block] as unknown as JsonValue),
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

/**
 * What a result adds to the client's influence: its verified labels, or untrusted content; nothing for a refusal or
 * when Paztport is off, and nothing in any session for a client that does not act on `influence`.
 */
export type ResultInfluence =
  | { kind: "labels"; labels: ContentLabel[]; hash: string }
  | { kind: "untrusted"; hash: string }
  | { kind: "none" };

/**
 * The session a result arrived in, with the client's own extension settings. Off records nothing, so it hashes
 * nothing. In an unsafe session a client that acts on `influence` counts every result untrusted (spec sessions.md,
 * Unsafe sessions), and one that does not reads no influence. An attested call's response is verified against the
 * server's root and keyring, with the client's settings, and must end at `svc`, the client's own service that made
 * the call; `now` is read only when it is.
 */
export type ResultContext =
  | { session: "off" }
  | {
      session: "unsafe";
      /** The extensions the client acts on: whether it counts the result untrusted. */
      extensions: ExtensionSettings;
    }
  | {
      session: "attested";
      reply: SessionReply;
      svc: string;
      rid: string;
      callId: string;
      allowedOrigins: string[];
      nonces: NonceCache;
      now: () => number;
      /** The extensions the client acts on and carries: check 9b and 9c's sets, and the names it reads. */
      extensions: ExtensionSettings;
    };

/**
 * How a tools/call result reads. A refusal (a non-audit verdict) means the tool did not run, and
 * nothing of it is recorded. A malformed result is one JCS cannot hash (a lone surrogate, a number
 * that parsed to Infinity); nothing of it is recorded either. A withheld result is a response whose last block
 * requires an extension the client does not act on (check 9c): the application MUST NOT hand it on, and fails the
 * call without retrying it, since the tool ran (spec verification.md, The live order); the reading holds nothing of
 * the result but, for a client that acts on `influence`, its hash for one untrusted entry. `verifiedAt` is the time
 * verification used.
 */
export type ToolResultReading =
  | { kind: "refused"; verdict: string; influence: { kind: "none" } }
  | { kind: "malformed"; verifiedAt?: number }
  | { kind: "withheld"; reason: "EXTENSION_REQUIRED"; verifiedAt: number; influence: ResultInfluence }
  | { kind: "read"; verdict?: string; verification?: string; verifiedAt?: number; influence: ResultInfluence };

/**
 * Reads a tools/call result: its verdict, its verification and what it adds to influence. In an attested session a
 * client that acts on `influence` takes the labels of a response that verified, every block of which names
 * `influence` with only labels under it (responseLabels), and counts any other result untrusted (spec influence.md,
 * Content labels); one that does not act on it reads no influence. In an unsafe session a client that acts on
 * `influence` counts every result that is not a refusal untrusted. Never throws.
 */
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
    const readsInfluence = ctx.extensions.actsOn.has(INFLUENCE);
    const untrusted: ResultInfluence = readsInfluence ? { kind: "untrusted", hash } : { kind: "none" };
    if (ctx.session === "unsafe" || ctx.reply.serverRoot === null) {
      return { kind: "read", ...withVerdict, influence: untrusted };
    }
    verifiedAt = ctx.now();
    // the session's one server keyring and root, each held to the reply's response limit
    const policyNotAfter = serverPolicyNotAfter(ctx.reply);
    const v = verifyMcpResponse(raw, { rid: ctx.rid, toolCallId: ctx.callId, receiver: ctx.svc }, {
      keyrings: [{ keys: ctx.reply.serverKeyring, notAfter: policyNotAfter }],
      roots: [
        { root: decode(ctx.reply.serverRoot.root), rootId: ctx.reply.serverRoot.rootId, notAfter: policyNotAfter },
      ],
      allowedOrigins: ctx.allowedOrigins,
      sess: ctx.reply.sess,
      nonces: ctx.nonces,
      now: verifiedAt,
      policyNotAfter,
      extensions: ctx.extensions,
    });
    if (v.reason === "EXTENSION_REQUIRED") {
      return { kind: "withheld", reason: "EXTENSION_REQUIRED", verifiedAt, influence: untrusted };
    }
    // A hand-over without `influence` takes no label, so a client never believes more than it was handed.
    const labels = readsInfluence ? responseLabels(v.reason, v.handOver?.get(INFLUENCE)) : null;
    const influence: ResultInfluence = labels === null ? untrusted : { kind: "labels", labels, hash };
    return { kind: "read", ...withVerdict, verification: v.reason, verifiedAt, influence };
  } catch {
    return { kind: "malformed", ...(verifiedAt !== undefined ? { verifiedAt } : {}) };
  }
}
