// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode } from "./b64url.ts";
import { decodeChainV1 } from "./chain.ts";
import { bindHttp } from "./binding.ts";
import { verify } from "./crypto.ts";
import { decodeProof, verifyProof } from "./merkle.ts";
import type { NonceCache } from "./nonce.ts";
import type { ReasonCode, VerifyResult } from "./reason.ts";
import { signingBytesV1, type StampV1 } from "./stamp.ts";

export type V1Config = {
  keyring: Record<string, string>;
  root: Uint8Array;
  rootId: string;
  allowedOrigins: string[];
  maxAgeMs: number;
  receivingService: string;
  nonces: NonceCache;
  now: number;
};

export type V1Request = { chainHeader?: string; proofHeader?: string; method: string; path: string; body: Uint8Array };

function reject(reason: ReasonCode, suspectSvc = "", suspectInst = ""): VerifyResult {
  return { ok: false, reason, suspectSvc, suspectInst };
}

function signatureValid(publicKey: string, s: StampV1): boolean {
  try {
    return verify(publicKey, signingBytesV1(s), decode(s.sig));
  } catch {
    return false;
  }
}

function pathAllowed(proofHeader: string | undefined, route: string, cfg: V1Config): boolean {
  if (proofHeader === undefined || proofHeader.trim() === "") {
    return false;
  }
  try {
    const proof = decodeProof(proofHeader);
    return proof.rootId === cfg.rootId && verifyProof(proof, route, cfg.root);
  } catch {
    return false;
  }
}

export function verifyV1(req: V1Request, cfg: V1Config): VerifyResult {
  // 1. Chain header present and parseable, with at least one stamp.
  if (req.chainHeader === undefined || req.chainHeader.trim() === "") {
    return reject("CHAIN_MISSING");
  }
  let stamps: StampV1[];
  try {
    stamps = decodeChainV1(req.chainHeader);
  } catch {
    return reject("CHAIN_MISSING");
  }
  if (stamps.length === 0) {
    return reject("CHAIN_MISSING");
  }

  const first = stamps[0]!;
  const last = stamps[stamps.length - 1]!;
  // Only PATH_NOT_ALLOWED names a suspect: by then the signatures, links, freshness, binding and
  // replay checks held, so the last hop's service really sent this request (its inst is that service's
  // own claim). Earlier failures may carry an unsigned name or another service's genuine stamp from a
  // replayed or altered capture.
  const fail = (reason: ReasonCode) => reject(reason);

  // 2. First stamp's svc is an allowed origin.
  if (!cfg.allowedOrigins.includes(first.svc)) {
    return fail("BAD_ORIGIN");
  }

  // 3. Every signature verifies, and each prev links to the previous sig.
  for (let i = 0; i < stamps.length; i++) {
    const s = stamps[i]!;
    const key = Object.hasOwn(cfg.keyring, s.svc) ? cfg.keyring[s.svc] : undefined;
    if (key === undefined || !signatureValid(key, s)) {
      return fail("BAD_SIGNATURE");
    }
    const expectedPrev = i === 0 ? "" : stamps[i - 1]!.sig;
    if (s.prev !== expectedPrev) {
      return fail("BROKEN_LINK");
    }
  }

  // 4. All stamps share the origin's rid; the origin ts is within max age.
  const rid = first.rid;
  if (stamps.some((s) => s.rid !== rid)) {
    return fail("RID_MISMATCH");
  }
  if (cfg.now - first.ts > cfg.maxAgeMs) {
    return fail("EXPIRED");
  }

  // 5. Last stamp's bind matches the request actually received.
  if (bindHttp(req.method, req.path, req.body) !== last.bind) {
    return fail("BINDING_MISMATCH");
  }

  // 6. (rid, last svc) not seen before.
  if (cfg.nonces.seenBefore(`${rid}|${last.svc}`, cfg.now)) {
    return fail("REPLAY");
  }

  // 7. Route rebuilt from the stamps plus this service, proven against the root.
  const route = stamps.map((s) => s.svc).join("/") + "/" + cfg.receivingService;
  if (!pathAllowed(req.proofHeader, route, cfg)) {
    return reject("PATH_NOT_ALLOWED", last.svc, last.inst);
  }

  return { ok: true, reason: "OK", suspectSvc: last.svc, suspectInst: last.inst };
}
