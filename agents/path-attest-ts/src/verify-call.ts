// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { bindMcpCall } from "./binding.ts";
import { parseInfluence, type InfluenceEntry } from "./influence.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF } from "./meta.ts";
import type { ReasonCode, VerifyResult } from "./reason.ts";
import { parseStampsV2 } from "./stamp.ts";
import { verifyChainV2, type V2Config } from "./verify-v2.ts";

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
    const meta = params._meta;
    const id = meta[META_CALL_ID];
    if (typeof id !== "string") {
      return fail("CHAIN_MISSING");
    }
    callId = id;
    const chain = meta[META_CHAIN];
    rid = parseStampsV2(chain)[0]!.rid;
    let expectedBind: string;
    try {
      expectedBind = bindMcpCall(params.name, callId, params.arguments ?? {});
    } catch {
      return fail("BINDING_MISMATCH");
    }
    const result = verifyChainV2(
      {
        stamps: chain,
        expectedBind,
        influence: meta[META_INFLUENCE] as InfluenceEntry[],
        proof: meta[META_PROOF],
        receiver: `mcp:${ctx.serverId}.${params.name}`,
      },
      { ...cfg, nonceKey: `${rid}|${callId}|req` },
    );
    return result.ok
      ? { result, rid, callId, influence: parseInfluence(meta[META_INFLUENCE]) }
      : { result, rid, callId, influence: [] };
  } catch {
    return fail("CHAIN_MISSING");
  }
}
