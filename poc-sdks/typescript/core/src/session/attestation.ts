// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "../encoding/b64url.ts";
import { sha256, utf8 } from "../crypto/crypto.ts";
import { bindResult } from "../stamp/binding.ts";
import { blocksOf, type Block } from "../stamp/block.ts";
import { readToken, type JsonObject } from "../encoding/json.ts";
import { exactly, object, str } from "../internal/fields.ts";
import { parseProof, type MerkleProof } from "../policy/merkle.ts";
import { nonceKey } from "../verify/nonce.ts";
import type { ReasonCode } from "../verify/reason.ts";
import { chainOf, type Stamp } from "../stamp/stamp.ts";
import { verifyChainRead, type ChainVerification, type VerifierConfig } from "../verify/verify-chain.ts";

/**
 * A response's attestation: the server's stamps, the last naming the calling client as its receiver, one block per
 * stamp, the proof of the server's route, and the result hash.
 */
export type ResponseAttestation = { blocks: Block[]; chain: Stamp[]; proof: MerkleProof; resultHash: string };
/** The call a response answers, and the client it was sent to: the service that made the call. */
type ResponseCall = { rid: string; callId: string; receiver: string };

/**
 * The value the last response stamp binds (spec wire.md, Bindings, Response): `b64url(H(utf8(resultHash ‖ "\n" ‖
 * callId)))`. Throws on a call id holding a newline, and on a lone surrogate in either, which has no UTF-8 form.
 */
export function bindResponse(resultHash: string, callId: string): string {
  if (callId.includes("\n")) {
    throw new Error("callId must not contain newlines");
  }
  return encode(sha256(utf8(resultHash + "\n" + callId)));
}

/**
 * The attestation's object by its schema (spec wire.md, Carrying a chain, MCP): exactly `blocks`, `chain`, `proof` and
 * `resultHash`, `blocks` an array of blocks. A count of blocks other than the chain's, or a block that does not match
 * its stamp, reads: check 9a refuses it.
 */
function attestationOf(o: JsonObject): ResponseAttestation {
  exactly(o, ["blocks", "chain", "proof", "resultHash"]);
  return {
    blocks: blocksOf(o.blocks!),
    chain: chainOf(o.chain!),
    proof: parseProof(o.proof!),
    resultHash: str(o, "resultHash"),
  };
}

/**
 * Reads a response attestation from its token: MalformedJson for bytes that do not read, an Error naming the member
 * for an attestation the schema refuses. Its blocks are read as blocks, its chain as a chain, its proof as a proof.
 */
export function readAttestation(token: string): ResponseAttestation {
  return attestationOf(object(readToken(token)));
}

/**
 * Verifies a response received live, given its attestation's token (spec verification.md, The MCP server and client,
 * A response, on the client): its last stamp naming `call.receiver`, the client that made the call. The route is the
 * server's own, so the receiver is off it. Never throws: an attestation that does not read is CHAIN_MISSING, and the
 * hand-over of the attestation's blocks comes with OK only, as `verifyChain` gives it.
 */
export function verifyResponse(
  attestation: string,
  result: Record<string, unknown>,
  call: ResponseCall,
  cfg: Omit<VerifierConfig, "nonceKey">,
): ChainVerification {
  const fail = (reason: ReasonCode): ChainVerification => ({
    ok: false, reason, suspectSvc: "", suspectInst: "", handOver: null,
  });
  try {
    if (typeof call?.rid !== "string" || typeof call.callId !== "string" || call.callId.includes("\n") || typeof call.receiver !== "string") {
      return fail("CHAIN_MISSING");
    }
    const read = object(readToken(attestation));
    const att = attestationOf(read);
    if (att.chain[0]!.rid !== call.rid) {
      return fail("RID_MISMATCH");
    }
    let expectedBind: string;
    try {
      if (att.resultHash !== bindResult(result)) {
        return fail("BINDING_MISMATCH");
      }
      expectedBind = bindResponse(att.resultHash, call.callId);
    } catch {
      return fail("BINDING_MISMATCH");
    }
    // The blocks as read, never null: `attestationOf` has read them as an array of blocks, so they are not taken for
    // an absent token.
    return verifyChainRead(
      {
        chain: read.chain,
        expectedBind,
        blocks: read.blocks!,
        proof: read.proof,
        receiver: call.receiver,
        receiverInRoute: false,
      },
      { ...cfg, nonceKey: nonceKey([call.rid, call.callId, "resp"]) },
    );
  } catch {
    return fail("CHAIN_MISSING");
  }
}
