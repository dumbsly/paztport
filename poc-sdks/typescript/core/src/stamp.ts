// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "./b64url.ts";
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

export type StampV2 = {
  v: 2;
  svc: string;
  inst: string;
  rid: string;
  ts: number;
  sess: string;
  bind: string;
  infl: string;
  prev: string;
  sig: string;
};

const LONE_SURROGATE = /\p{Surrogate}/u;
const V2_STRING_FIELDS = ["svc", "inst", "rid", "sess", "bind", "infl", "prev"] as const;

/** The exact bytes covered by a v2 stamp's signature; throws if any string field contains the delimiter. */
export function signingBytesV2(s: Omit<StampV2, "sig">): Uint8Array {
  for (const f of V2_STRING_FIELDS) {
    if (s[f].includes("|")) {
      throw new Error(`stamp field ${f} must not contain '|'`);
    }
    if (LONE_SURROGATE.test(s[f])) {
      throw new Error(`stamp field ${f} must not contain a lone surrogate`);
    }
  }
  return utf8(`2|${s.svc}|${s.inst}|${s.rid}|${s.ts}|${s.sess}|${s.bind}|${s.infl}|${s.prev}`);
}

export function signStampV2(fields: Omit<StampV2, "sig" | "v">, privateKey: string): StampV2 {
  const base = {
    v: 2 as const,
    svc: fields.svc,
    inst: fields.inst,
    rid: fields.rid,
    ts: fields.ts,
    sess: fields.sess,
    bind: fields.bind,
    infl: fields.infl,
    prev: fields.prev,
  };
  return { ...base, sig: encode(sign(privateKey, signingBytesV2(base))) };
}

/** Throws unless value is a non-empty array of objects with exactly-typed v2 stamp fields. */
export function parseStampsV2(value: unknown): StampV2[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("stamps must be a non-empty array");
  }
  return value.map((item) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error("stamp must be an object");
    }
    const o = item as Record<string, unknown>;
    if (o.v !== 2 || typeof o.ts !== "number" || !Number.isSafeInteger(o.ts)) {
      throw new Error("malformed stamp");
    }
    for (const f of [...V2_STRING_FIELDS, "sig"] as const) {
      if (typeof o[f] !== "string") {
        throw new Error(`malformed stamp field ${f}`);
      }
      if (LONE_SURROGATE.test(o[f] as string)) {
        throw new Error(`lone surrogate in stamp field ${f}`);
      }
    }
    if (encode(decode(o.sig as string)) !== o.sig) {
      throw new Error("non-canonical signature encoding");
    }
    return {
      v: 2,
      svc: o.svc as string,
      inst: o.inst as string,
      rid: o.rid as string,
      ts: o.ts,
      sess: o.sess as string,
      bind: o.bind as string,
      infl: o.infl as string,
      prev: o.prev as string,
      sig: o.sig as string,
    };
  });
}
