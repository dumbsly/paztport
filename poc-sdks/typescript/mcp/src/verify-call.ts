// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { parseInfluence, parseStampsV2, verifyChainV2 } from "@paztport/core";
import type { InfluenceEntry, ReasonCode, V2Config, VerifyResult } from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF } from "./meta.ts";

export type CallVerification = { result: VerifyResult; rid: string; callId: string; influence: InfluenceEntry[] };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
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
    if (/[/|]/.test(params.name) || /[/|.]/.test(ctx.serverId)) {
      return fail("CHAIN_MISSING");
    }
    const meta = params._meta;
    const id = meta[META_CALL_ID];
    if (typeof id !== "string") {
      return fail("CHAIN_MISSING");
    }
    callId = id;
    // Read each _meta field once and parse once; verifyChainV2 re-parsing parsed values is idempotent.
    const stamps = parseStampsV2(meta[META_CHAIN]);
    rid = stamps[0]!.rid;
    const rawInfluence = meta[META_INFLUENCE];
    const proof = meta[META_PROOF];
    let influence: InfluenceEntry[] | undefined;
    try {
      influence = parseInfluence(rawInfluence);
    } catch {
      // unparsable influence is rejected by verifyChainV2 in its own check order
    }
    let expectedBind: string;
    try {
      expectedBind = bindMcpCall(params.name, callId, params.arguments ?? {});
    } catch {
      return fail("BINDING_MISMATCH");
    }
    const result = verifyChainV2(
      {
        stamps,
        expectedBind,
        influence: influence ?? (rawInfluence as InfluenceEntry[]),
        proof,
        receiver: `mcp:${ctx.serverId}.${params.name}`,
      },
      { ...cfg, nonceKey: `${rid}|${callId}|req` },
    );
    return result.ok
      ? { result, rid, callId, influence: influence! }
      : { result, rid, callId, influence: [] };
  } catch {
    return fail("CHAIN_MISSING");
  }
}
