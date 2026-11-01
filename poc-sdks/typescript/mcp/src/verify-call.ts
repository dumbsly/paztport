// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  CALL_MAX_AGE_MS,
  readChain,
  readInfluence,
  RUN_MAX_AGE_MS,
  verifyChainOffline,
  verifyChainV3,
  writeToken,
} from "@paztport/core";
import type { InfluenceEntry, JsonValue, OfflineConfig, ReasonCode, V3Config, V3Input, VerifyResult } from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF } from "./meta.ts";

/** A call's verdict, with the rid and call id it names and, when it verifies, its influence. */
export type CallVerification = { result: VerifyResult; rid: string; callId: string; influence: InfluenceEntry[] };

/** The receiver a tools/call names at the end of its route: `mcp:<serverId>.<tool>`. */
export function mcpReceiver(serverId: string, tool: string): string {
  return `mcp:${serverId}.${tool}`;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** `value`'s token, or `none` for a value no writer writes: "" is a token that does not read. */
function tokenOr<T extends string | null>(value: unknown, none: T): string | T {
  try {
    return writeToken(value as JsonValue);
  } catch {
    return none;
  }
}

/** Checks a call's chain once its params have been read: the chain, its nonce key and the call id it names. */
type ChainCheck = (input: Omit<V3Input, "peer">, nonceKey: string, callId: string) => VerifyResult;

/**
 * Reads a tools/call params object once, turns its `_meta` chain, influence and proof into the tokens the verifier
 * reads, reads the chain for its rid, derives the binding, the receiver `mcp:<serverId>.<name>` (on the route) and
 * the nonce key `rid|callId|req`, and hands them to `check`. A value no writer writes gets its reader's refusal: the
 * chain CHAIN_MISSING, the influence INFLUENCE_MISMATCH in the verifier's own check order, the proof none. Never
 * throws; influence is returned only when the call verifies.
 */
function checkCall(params: unknown, serverId: string, check: ChainCheck): CallVerification {
  let rid = "";
  let callId = "";
  const fail = (reason: ReasonCode): CallVerification => ({
    result: { ok: false, reason, suspectSvc: "", suspectInst: "" },
    rid,
    callId,
    influence: [],
  });
  try {
    if (!isObject(params) || typeof params.name !== "string" || !isObject(params._meta)) {
      return fail("CHAIN_MISSING");
    }
    // `/` would inject route segments, `|` is the field delimiter, `.` would make the receiver ambiguous.
    if (/[/|]/.test(params.name) || /[/|.]/.test(serverId)) {
      return fail("CHAIN_MISSING");
    }
    const meta = params._meta;
    const id = meta[META_CALL_ID];
    if (typeof id !== "string") {
      return fail("CHAIN_MISSING");
    }
    callId = id;
    const chain = tokenOr(meta[META_CHAIN], "");
    rid = readChain(chain)[0]!.rid;
    const influence = tokenOr(meta[META_INFLUENCE], "");
    const proof = tokenOr(meta[META_PROOF], null);
    let expectedBind: string;
    try {
      expectedBind = bindMcpCall(params.name, callId, params.arguments ?? {});
    } catch {
      return fail("BINDING_MISMATCH");
    }
    const result = check(
      {
        chain,
        expectedBind,
        influence,
        proof,
        receiver: mcpReceiver(serverId, params.name),
        receiverInRoute: true,
      },
      `${rid}|${callId}|req`,
      callId,
    );
    return { result, rid, callId, influence: result.ok ? readInfluence(influence) : [] };
  } catch {
    return fail("CHAIN_MISSING");
  }
}

/**
 * Server-side check of an MCP tools/call params object, whose chain must be v3.
 * Derives the binding, the receiver `mcp:<serverId>.<name>` and the nonce key `rid|callId|req` itself. Never
 * throws; influence is returned only when the call verifies.
 */
export function verifyCall(
  params: unknown,
  ctx: { serverId: string },
  cfg: Omit<V3Config, "nonceKey">,
): CallVerification {
  return checkCall(params, ctx.serverId, (input, nonceKey) => verifyChainV3(input, { ...cfg, nonceKey }));
}

/** Where a recorded tools/call is filed, and what the record set says about its run. */
export type RecordedCall = {
  serverId: string;
  /** The rid and call id the record files the call under; the call's chain must name them. */
  rid: string;
  callId: string;
  /** When the calling hop stamped the call, as recorded. */
  stampedAt: number;
  /** The run's recorded prompt; undefined when the run has none or it is in dispute. */
  prompt?: string;
};

/**
 * Offline check of a tools/call params object read back from a record set: the server-side check, with
 * verifyChainOffline in place of the live chain verifier. The calling hop recorded the call when it stamped it,
 * so the live window becomes its clock-free limits: the call within the run's lifetime of its origin, and the
 * origin not after the call by more than the call window (EXPIRED). A chain that verifies but is for another
 * call id than the record's is RID_MISMATCH. `cfg.seen` spans the whole record set. Never throws.
 */
export function verifyRecordedCall(params: unknown, call: RecordedCall, cfg: Omit<OfflineConfig, "nonceKey">): CallVerification {
  return checkCall(params, call.serverId, (input, nonceKey, callId) => {
    const result = verifyChainOffline(
      { ...input, rid: call.rid, recordedTs: { last: call.stampedAt }, prompt: call.prompt },
      { ...cfg, runMaxAgeMs: cfg.runMaxAgeMs ?? RUN_MAX_AGE_MS, callMaxAgeMs: cfg.callMaxAgeMs ?? CALL_MAX_AGE_MS, nonceKey },
    );
    return result.ok && callId !== call.callId ? { ok: false, reason: "RID_MISMATCH", suspectSvc: "", suspectInst: "" } : result;
  });
}
