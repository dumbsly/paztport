// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  CALL_MAX_AGE_MS,
  parseInfluence,
  parseStampsV3,
  RUN_MAX_AGE_MS,
  verifyChainOffline,
  verifyChainV3,
} from "@paztport/core";
import type { InfluenceEntry, OfflineConfig, ReasonCode, StampV3, V3Config, V3Input, VerifyResult } from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF } from "./meta.ts";

/** A call's verdict; `legacy` is false. */
export type CallVerification = { result: VerifyResult; rid: string; callId: string; influence: InfluenceEntry[]; legacy: boolean };

/** The receiver a tools/call names at the end of its route: `mcp:<serverId>.<tool>`. */
export function mcpReceiver(serverId: string, tool: string): string {
  return `mcp:${serverId}.${tool}`;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Reads a call's chain, throwing on one the verifier would not take. */
type StampParser = (value: unknown) => StampV3[];

/** Checks a call's chain once its params have been read: the chain, its nonce key and the call id it names. */
type ChainCheck = (input: Omit<V3Input, "peer">, nonceKey: string, callId: string) => VerifyResult & { legacy: boolean };

/**
 * Reads a tools/call params object once, parses its chain with `parse`, derives the binding, the receiver
 * `mcp:<serverId>.<name>` (on the route) and the nonce key `rid|callId|req`, and hands them to `check`. Never
 * throws; influence is returned only when the call verifies.
 */
function checkCall(params: unknown, serverId: string, parse: StampParser, check: ChainCheck): CallVerification {
  let rid = "";
  let callId = "";
  const fail = (reason: ReasonCode): CallVerification => ({
    result: { ok: false, reason, suspectSvc: "", suspectInst: "" },
    rid,
    callId,
    influence: [],
    legacy: false,
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
    const stamps = parse(meta[META_CHAIN]);
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
    const { legacy, ...result } = check(
      {
        stamps,
        expectedBind,
        influence: influence ?? (rawInfluence as InfluenceEntry[]),
        proof,
        receiver: mcpReceiver(serverId, params.name),
        receiverInRoute: true,
      },
      `${rid}|${callId}|req`,
      callId,
    );
    return { result, rid, callId, influence: result.ok ? influence! : [], legacy };
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
  return checkCall(params, ctx.serverId, parseStampsV3, (input, nonceKey) => ({ ...verifyChainV3(input, { ...cfg, nonceKey }), legacy: false }));
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
  return checkCall(params, call.serverId, parseStampsV3, (input, nonceKey, callId) => {
    const result = verifyChainOffline(
      { ...input, rid: call.rid, recordedTs: { last: call.stampedAt }, prompt: call.prompt },
      { ...cfg, runMaxAgeMs: cfg.runMaxAgeMs ?? RUN_MAX_AGE_MS, callMaxAgeMs: cfg.callMaxAgeMs ?? CALL_MAX_AGE_MS, nonceKey },
    );
    return result.ok && callId !== call.callId ? { ok: false, reason: "RID_MISMATCH", suspectSvc: "", suspectInst: "", legacy: result.legacy } : result;
  });
}
