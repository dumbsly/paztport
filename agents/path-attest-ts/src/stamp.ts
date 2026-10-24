// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { encode } from "./b64url.ts";
import { sign, utf8 } from "./crypto.ts";

export type StampV1 = { svc: string; inst: string; rid: string; ts: number; bind: string; prev: string; sig: string };

/** The exact bytes covered by a v1 stamp's signature. */
export function signingBytesV1(s: Omit<StampV1, "sig">): Uint8Array {
  return utf8(`${s.svc}|${s.inst}|${s.rid}|${s.ts}|${s.bind}|${s.prev}`);
}

export function signStampV1(fields: Omit<StampV1, "sig">, privateKey: string): StampV1 {
  const base = { svc: fields.svc, inst: fields.inst, rid: fields.rid, ts: fields.ts, bind: fields.bind, prev: fields.prev };
  return { ...base, sig: encode(sign(privateKey, signingBytesV1(base))) };
}
