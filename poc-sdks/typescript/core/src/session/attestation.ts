// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "../encoding/b64url.ts";
import { randomBytes, sha256, utf8 } from "../crypto/crypto.ts";
import { bindResult } from "../stamp/binding.ts";
import type { InfluenceClass } from "../influence/influence.ts";
import { canonicalize } from "../encoding/jcs.ts";
import type { MerkleProof } from "../policy/merkle.ts";
import type { VerifyResult } from "../verify/reason.ts";
import type { StampV3 } from "../stamp/stamp.ts";
import { verifyChainAcceptingLegacy, verifyChainV3, type V3Config, type V3Input } from "../verify/verify-v3.ts";

export type ContentLabel = { cls: InfluenceClass; cid: string; owner?: string };
/** A response's attestation: the server's stamps, the last naming the calling client as its receiver. */
export type ResponseAttestation = { chain: StampV3[]; proof: MerkleProof; labels: ContentLabel[]; resultHash: string };
/** The call a response answers, and the client it was sent to: the service that made the call. */
type ResponseCall = { rid: string; toolCallId: string; receiver: string };

const CLASSES: readonly string[] = ["third-party", "private", "public", "local-untrusted"];

export function newContentId(): string {
  return encode(randomBytes(16));
}

/** The value the last response stamp binds: covers the result hash, the call id and the labels. */
export function bindResponse(resultHash: string, toolCallId: string, labels: ContentLabel[]): string {
  if (toolCallId.includes("\n")) {
    throw new Error("toolCallId must not contain newlines");
  }
  return encode(sha256(utf8(resultHash + "\n" + toolCallId + "\n" + canonicalize(labels))));
}

/** The attestation's fields, its chain left for the verifier to parse (a recorded one may be legacy v2). */
function parseAttestation(att: unknown): (Omit<ResponseAttestation, "chain"> & { chain: unknown[] }) | null {
  if (typeof att !== "object" || att === null || Array.isArray(att)) {
    return null;
  }
  const a = att as Record<string, unknown>;
  if (!Array.isArray(a.chain) || typeof a.resultHash !== "string" || !Array.isArray(a.labels)) {
    return null;
  }
  const labels: ContentLabel[] = [];
  for (const l of a.labels) {
    if (typeof l !== "object" || l === null || Array.isArray(l)) {
      return null;
    }
    const o = l as Record<string, unknown>;
    if (typeof o.cls !== "string" || !CLASSES.includes(o.cls) || typeof o.cid !== "string") {
      return null;
    }
    if (o.owner !== undefined && (typeof o.owner !== "string" || o.owner === "")) {
      return null;
    }
    labels.push(o.owner === undefined ? { cls: o.cls as InfluenceClass, cid: o.cid } : { cls: o.cls as InfluenceClass, cid: o.cid, owner: o.owner });
  }
  return { chain: a.chain, proof: a.proof as MerkleProof, labels, resultHash: a.resultHash };
}

type ResponseCheck = { result: VerifyResult; labels: ContentLabel[]; legacy: boolean };

/** The response checks around one chain verifier; never throws. The route is the server's own, so its receiver is off it. */
function checkResponse(
  attestation: unknown,
  result: Record<string, unknown>,
  call: ResponseCall,
  cfg: Omit<V3Config, "nonceKey">,
  verifyChain: (input: V3Input, cfg: V3Config) => VerifyResult & { legacy?: boolean },
): ResponseCheck {
  const fail = (reason: VerifyResult["reason"]): ResponseCheck => ({
    result: { ok: false, reason, suspectSvc: "", suspectInst: "" },
    labels: [],
    legacy: false,
  });
  try {
    if (typeof call?.rid !== "string" || typeof call.toolCallId !== "string" || call.toolCallId.includes("\n") || typeof call.receiver !== "string") {
      return fail("CHAIN_MISSING");
    }
    const att = parseAttestation(attestation);
    if (att === null) {
      return fail("CHAIN_MISSING");
    }
    const head: unknown = att.chain[0];
    if (typeof head === "object" && head !== null && (head as Record<string, unknown>).rid !== call.rid) {
      return fail("RID_MISMATCH");
    }
    if (att.resultHash !== bindResult(result)) {
      return fail("BINDING_MISMATCH");
    }
    const { legacy = false, ...r } = verifyChain(
      {
        stamps: att.chain,
        expectedBind: bindResponse(att.resultHash, call.toolCallId, att.labels),
        influence: [],
        proof: att.proof,
        receiver: call.receiver,
        receiverInRoute: false,
      },
      { ...cfg, nonceKey: `${call.rid}|${call.toolCallId}|resp` },
    );
    return { result: r, labels: r.ok ? att.labels : [], legacy };
  } catch {
    return fail("CHAIN_MISSING");
  }
}

/**
 * Verifies a response received live: v3 only, its last stamp naming `call.receiver`. Never throws; labels are
 * returned only when the whole response verifies for this call.
 */
export function verifyResponse(
  attestation: unknown,
  result: Record<string, unknown>,
  call: ResponseCall,
  cfg: Omit<V3Config, "nonceKey">,
): { result: VerifyResult; labels: ContentLabel[] } {
  const { legacy: _legacy, ...r } = checkResponse(attestation, result, call, cfg, verifyChainV3);
  return r;
}

/** verifyResponse for a recorded response, which may also be a legacy v2 one (with no receiver to check); never throws. */
export function recheckResponse(
  attestation: unknown,
  result: Record<string, unknown>,
  call: ResponseCall,
  cfg: Omit<V3Config, "nonceKey">,
): { result: VerifyResult; labels: ContentLabel[]; legacy: boolean } {
  return checkResponse(attestation, result, call, cfg, verifyChainAcceptingLegacy);
}
