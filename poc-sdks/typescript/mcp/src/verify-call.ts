// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  nonceKey,
  readChain,
  verifyChainOffline,
  verifyChain,
} from "@paztport/core";
import type {
  ChainVerification, OfflineConfig, ReasonCode, VerifierConfig, VerifyInput,
} from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_CALL_ID, META_CHAIN, META_EXTENSIONS, META_PROOF } from "./meta.ts";

/**
 * A call's verdict, with the rid and call id it names. The verdict carries the hand-over, the items under each
 * extension the verifier acts on, exactly when it is OK.
 */
export type CallVerification = { result: ChainVerification; rid: string; callId: string };

/** The receiver a tools/call names at the end of its route: `mcp:<serverId>.<tool>`. */
export function mcpReceiver(serverId: string, tool: string): string {
  return `mcp:${serverId}.${tool}`;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** `value` when it is a string, a token for the verifier to read; else `none`, which its reader refuses. */
function tokenOr<T extends string | null>(value: unknown, none: T): string | T {
  return typeof value === "string" ? value : none;
}

/** Checks a call's chain once its params have been read: the chain, its nonce key and the call id it names. */
type ChainCheck = (input: Omit<VerifyInput, "peer">, key: string, callId: string) => ChainVerification;

/**
 * Reads a tools/call params object once: its `_meta` chain, blocks and proof are the tokens the verifier reads.
 * Reads the chain for its rid, derives the binding, the receiver `mcp:<serverId>.<name>` (on the route) and the nonce
 * key `JCS([rid, callId, "req"])`, and hands them to `check`. A member that is not a string gets its reader's refusal:
 * the chain CHAIN_MISSING ("" is a token that does not read), the blocks EXTENSION_MISMATCH in the verifier's own
 * check order, the proof none. No `paztport/extensions` member is every block empty. Never throws.
 */
function checkCall(params: unknown, serverId: string, check: ChainCheck): CallVerification {
  let rid = "";
  let callId = "";
  const fail = (reason: ReasonCode): CallVerification => ({
    result: { ok: false, reason, suspectSvc: "", suspectInst: "", handOver: null },
    rid,
    callId,
  });
  try {
    if (!isObject(params) || typeof params.name !== "string" || !isObject(params._meta)) {
      return fail("CHAIN_MISSING");
    }
    // The receiver `mcp:<serverId>.<name>` is a route node, which holds no `/` or `|` (spec wire.md, Routes), and a
    // `.` in the server id would let two server and tool pairs name one receiver.
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
    const blocks = Object.hasOwn(meta, META_EXTENSIONS) ? tokenOr(meta[META_EXTENSIONS], "") : null;
    const proof = tokenOr(meta[META_PROOF], null);
    let expectedBind: string;
    try {
      expectedBind = bindMcpCall(params.name, callId, params.arguments ?? {});
    } catch {
      return fail("BINDING_MISMATCH");
    }
    // The binding has refused a call id holding a lone surrogate, the one string a nonce key cannot be formed from.
    const result = check(
      {
        chain,
        expectedBind,
        blocks,
        proof,
        receiver: mcpReceiver(serverId, params.name),
        receiverInRoute: true,
      },
      nonceKey([rid, callId, "req"]),
      callId,
    );
    return { result, rid, callId };
  } catch {
    return fail("CHAIN_MISSING");
  }
}

/**
 * Server-side check of an MCP tools/call params object (spec verification.md, The MCP server and client): derives the
 * binding, the receiver `mcp:<serverId>.<name>` and the nonce key itself, and runs the live order with `cfg`'s
 * extension settings, so the hand-over holds the items under each extension the server acts on. Never throws.
 */
export function verifyCall(
  params: unknown,
  ctx: { serverId: string },
  cfg: Omit<VerifierConfig, "nonceKey">,
): CallVerification {
  return checkCall(params, ctx.serverId, (input, key) => verifyChain(input, { ...cfg, nonceKey: key }));
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
 * verifyChainOffline in place of the live chain verifier. The calling hop recorded the call when it stamped it, so the
 * live window becomes its clock-free limits: the call within the run's lifetime of its origin, and the origin not after
 * the call by more than the call window (EXPIRED), each limit `cfg`'s or its live default. A chain that verifies but is
 * for another call id than the record's is RID_MISMATCH. `cfg.seen` spans the whole record set. A session's keyring
 * and root are passed with no window (`notAfter: Infinity`), since callInSession judges the session's limits. Of the
 * extension checks it runs 9a, and 9b with an allowed list, never 9c: the call was held to the server's `actsOn` live.
 * A verifier that acts on an extension applies its reading of the items to an OK result before the session's limits:
 * for influence, `recordedCallReason` does both in that order, so a call past its session's limits that holds an item
 * that does not read gets the extension's code. Never throws.
 */
export function verifyRecordedCall(params: unknown, call: RecordedCall, cfg: Omit<OfflineConfig, "nonceKey">): CallVerification {
  return checkCall(params, call.serverId, (input, key, callId) => {
    const result = verifyChainOffline(
      { ...input, rid: call.rid, recordedTs: { last: call.stampedAt }, prompt: call.prompt },
      { ...cfg, nonceKey: key },
    );
    return result.ok && callId !== call.callId
      ? { ok: false, reason: "RID_MISMATCH", suspectSvc: "", suspectInst: "", handOver: null }
      : result;
  });
}
