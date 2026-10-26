// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "./b64url.ts";
import { randomBytes, sha256, utf8 } from "./crypto.ts";
import { bindResult } from "./binding.ts";
import type { InfluenceClass } from "./influence.ts";
import { canonicalize } from "./jcs.ts";
import type { MerkleProof } from "./merkle.ts";
import type { VerifyResult } from "./reason.ts";
import type { StampV2 } from "./stamp.ts";
import { verifyChainV2, type V2Config } from "./verify-v2.ts";

export type ContentLabel = { cls: InfluenceClass; cid: string; owner?: string };
export type ResponseAttestation = { chain: StampV2[]; proof: MerkleProof; labels: ContentLabel[]; resultHash: string };

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

function parseAttestation(att: unknown): ResponseAttestation | null {
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
  return { chain: a.chain as StampV2[], proof: a.proof as MerkleProof, labels, resultHash: a.resultHash };
}

/** Never throws; labels are returned only when the whole response verifies for this call. */
export function verifyResponse(
  attestation: unknown,
  result: Record<string, unknown>,
  call: { rid: string; toolCallId: string },
  cfg: Omit<V2Config, "nonceKey">,
): { result: VerifyResult; labels: ContentLabel[] } {
  const fail = (reason: VerifyResult["reason"]) => ({
    result: { ok: false, reason, suspectSvc: "", suspectInst: "" } as VerifyResult,
    labels: [] as ContentLabel[],
  });
  try {
    if (typeof call?.rid !== "string" || typeof call.toolCallId !== "string" || call.toolCallId.includes("\n")) {
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
    const r = verifyChainV2(
      {
        stamps: att.chain,
        expectedBind: bindResponse(att.resultHash, call.toolCallId, att.labels),
        influence: [],
        proof: att.proof,
      },
      { ...cfg, nonceKey: `${call.rid}|${call.toolCallId}|resp` },
    );
    return r.ok ? { result: r, labels: att.labels } : { result: r, labels: [] };
  } catch {
    return fail("CHAIN_MISSING");
  }
}
