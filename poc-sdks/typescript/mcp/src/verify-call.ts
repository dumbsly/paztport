// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { CALL_MAX_AGE_MS, parseInfluence, parseStampsV2, RUN_MAX_AGE_MS, verifyChainOffline, verifyChainV2 } from "@paztport/core";
import type { InfluenceEntry, OfflineConfig, ReasonCode, V2Config, V2Input, VerifyResult } from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF } from "./meta.ts";

export type CallVerification = { result: VerifyResult; rid: string; callId: string; influence: InfluenceEntry[] };

/** The receiver a tools/call names at the end of its route: `mcp:<serverId>.<tool>`. */
export function mcpReceiver(serverId: string, tool: string): string {
  return `mcp:${serverId}.${tool}`;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Checks a call's chain once its params have been read: the chain, its nonce key and the call id it names. */
type ChainCheck = (input: V2Input, nonceKey: string, callId: string) => VerifyResult;

/**
 * Reads a tools/call params object once, derives the binding, the receiver `mcp:<serverId>.<name>` and the
 * nonce key `rid|callId|req`, and hands them to `check`. Never throws; influence is returned only when the
 * call verifies.
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
    // Read each _meta field once and parse once; the chain verifier re-parsing parsed values is idempotent.
    const stamps = parseStampsV2(meta[META_CHAIN]);
    rid = stamps[0]!.rid;
    const rawInfluence = meta[META_INFLUENCE];
    const proof = meta[META_PROOF];
    let influence: InfluenceEntry[] | undefined;
    try {
      influence = parseInfluence(rawInfluence);
    } catch {
      // unparsable influence is rejected by the chain verifier in its own check order
    }
    let expectedBind: string;
    try {
      expectedBind = bindMcpCall(params.name, callId, params.arguments ?? {});
    } catch {
      return fail("BINDING_MISMATCH");
    }
    const result = check(
      {
        stamps,
        expectedBind,
        influence: influence ?? (rawInfluence as InfluenceEntry[]),
        proof,
        receiver: mcpReceiver(serverId, params.name),
      },
      `${rid}|${callId}|req`,
      callId,
    );
    return result.ok
      ? { result, rid, callId, influence: influence! }
      : { result, rid, callId, influence: [] };
  } catch {
    return fail("CHAIN_MISSING");
  }
}

/**
 * Server-side check of an MCP tools/call params object. Derives the binding, the receiver
 * `mcp:<serverId>.<name>` and the nonce key `rid|callId|req` itself. Never throws; influence
 * is returned only when the call verifies.
 */
export function verifyCall(
  params: unknown,
  ctx: { serverId: string },
  cfg: Omit<V2Config, "nonceKey">,
): CallVerification {
  return checkCall(params, ctx.serverId, (input, nonceKey) => verifyChainV2(input, { ...cfg, nonceKey }));
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
      { runMaxAgeMs: RUN_MAX_AGE_MS, callMaxAgeMs: CALL_MAX_AGE_MS, ...cfg, nonceKey },
    );
    return result.ok && callId !== call.callId ? { ok: false, reason: "RID_MISMATCH", suspectSvc: "", suspectInst: "" } : result;
  });
}
