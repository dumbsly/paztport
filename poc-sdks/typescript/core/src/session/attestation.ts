// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "../encoding/b64url.ts";
import { concat, randomBytes, sha256, utf8 } from "../crypto/crypto.ts";
import { bindResult } from "../stamp/binding.ts";
import type { InfluenceClass } from "../influence/influence.ts";
import { writeWire } from "../encoding/jcs.ts";
import { readToken, type JsonObject, type JsonValue } from "../encoding/json.ts";
import { array, exactly, object, str } from "../internal/fields.ts";
import { parseProof, type MerkleProof } from "../policy/merkle.ts";
import type { VerifyResult } from "../verify/reason.ts";
import { chainOf, type StampV3 } from "../stamp/stamp.ts";
import { verifyChainRead, type V3Config } from "../verify/verify-v3.ts";

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
  return encode(sha256(concat(utf8(resultHash + "\n" + toolCallId + "\n"), writeWire(labels as JsonValue))));
}

/** A label by the schema: `cls` of a class, `cid` a string, and `owner` a non-empty string or absent. */
function labelOf(value: JsonValue): ContentLabel {
  const o = object(value);
  exactly(o, ["cls", "cid"], ["owner"]);
  const cls = str(o, "cls");
  if (!CLASSES.includes(cls)) {
    throw new Error("member cls is not a class");
  }
  const cid = str(o, "cid");
  if (!Object.hasOwn(o, "owner")) {
    return { cls: cls as InfluenceClass, cid };
  }
  const owner = str(o, "owner");
  if (owner === "") {
    throw new Error("member owner is empty");
  }
  return { cls: cls as InfluenceClass, cid, owner };
}

/** The attestation's object by its schema: exactly `chain`, `proof`, `labels` and `resultHash`. */
function attestationOf(o: JsonObject): ResponseAttestation {
  exactly(o, ["chain", "proof", "labels", "resultHash"]);
  return {
    chain: chainOf(o.chain!),
    proof: parseProof(o.proof!),
    labels: array(o, "labels").map(labelOf),
    resultHash: str(o, "resultHash"),
  };
}

/**
 * Reads a response attestation from its token: MalformedJson for bytes that do not read, an Error naming the member
 * for an attestation the schema refuses. Its chain is read as a chain, its proof as a proof, each label by the
 * label's schema.
 */
export function readAttestation(token: string): ResponseAttestation {
  return attestationOf(object(readToken(token)));
}

/**
 * Verifies a response received live, given its attestation's token: v3 only, its last stamp naming `call.receiver`,
 * the client that made the call. The route is the server's own, so the receiver is off it. Never throws; an
 * attestation that does not read is CHAIN_MISSING, and labels are returned only when the whole response verifies
 * for this call.
 */
export function verifyResponse(
  attestation: string,
  result: Record<string, unknown>,
  call: ResponseCall,
  cfg: Omit<V3Config, "nonceKey">,
): { result: VerifyResult; labels: ContentLabel[] } {
  const fail = (reason: VerifyResult["reason"]) => ({ result: { ok: false as const, reason, suspectSvc: "", suspectInst: "" }, labels: [] });
  try {
    if (typeof call?.rid !== "string" || typeof call.toolCallId !== "string" || call.toolCallId.includes("\n") || typeof call.receiver !== "string") {
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
      expectedBind = bindResponse(att.resultHash, call.toolCallId, att.labels);
    } catch {
      return fail("BINDING_MISMATCH");
    }
    const r = verifyChainRead(
      {
        chain: read.chain,
        expectedBind,
        influence: [],
        proof: read.proof,
        receiver: call.receiver,
        receiverInRoute: false,
      },
      { ...cfg, nonceKey: `${call.rid}|${call.toolCallId}|resp` },
    );
    return { result: r, labels: r.ok ? att.labels : [] };
  } catch {
    return fail("CHAIN_MISSING");
  }
}
