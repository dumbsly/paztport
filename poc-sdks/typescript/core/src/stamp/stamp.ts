// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { isWellFormed, sign, utf8 } from "../crypto/crypto.ts";
import { isProtocolText } from "../encoding/json-rules.ts";

/** Checks one stamp object's typed fields; returns it as a record. */
function checkStamp(item: unknown): Record<string, unknown> {
  if (typeof item !== "object" || item === null || Array.isArray(item)) {
    throw new Error("stamp must be an object");
  }
  const o = item as Record<string, unknown>;
  if (o.v !== 3 || typeof o.ts !== "number" || !Number.isSafeInteger(o.ts)) {
    throw new Error("malformed stamp");
  }
  for (const f of [...V3_STRING_FIELDS, "sig"]) {
    if (typeof o[f] !== "string") {
      throw new Error(`malformed stamp field ${f}`);
    }
    if (!isWellFormed(o[f] as string)) {
      throw new Error(`lone surrogate in stamp field ${f}`);
    }
  }
  decode(o.sig as string);
  return o;
}

function nonEmptyArray(value: unknown): unknown[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("stamps must be a non-empty array");
  }
  return value;
}

export type StampV3 = {
  v: 3;
  svc: string;
  inst: string;
  rid: string;
  ts: number;
  sess: string;
  rcv: string;
  bind: string;
  infl: string;
  prev: string;
  sig: string;
};

const V3_STRING_FIELDS = ["svc", "inst", "rid", "sess", "rcv", "bind", "infl", "prev"] as const;

/** The exact bytes covered by a v3 stamp's signature; throws if any string field contains the delimiter, a lone surrogate or a noncharacter. */
export function signingBytesV3(s: Omit<StampV3, "sig">): Uint8Array {
  for (const f of V3_STRING_FIELDS) {
    if (s[f].includes("|")) {
      throw new Error(`stamp field ${f} must not contain '|'`);
    }
    if (!isProtocolText(s[f])) {
      throw new Error(`stamp field ${f} must not contain a lone surrogate or a noncharacter`);
    }
  }
  return utf8(`3|${s.svc}|${s.inst}|${s.rid}|${s.ts}|${s.sess}|${s.rcv}|${s.bind}|${s.infl}|${s.prev}`);
}

/** Signs a v3 stamp, the one every live producer makes; throws if a field holds the delimiter, a lone surrogate or a noncharacter, or `ts` is outside [0, 2^53 − 1]. */
export function signStampV3(fields: Omit<StampV3, "sig" | "v">, privateKey: string): StampV3 {
  if (!Number.isSafeInteger(fields.ts) || fields.ts < 0) {
    throw new Error("stamp ts must be an integer in [0, 2^53 - 1]");
  }
  const base = {
    v: 3 as const,
    svc: fields.svc,
    inst: fields.inst,
    rid: fields.rid,
    ts: fields.ts,
    sess: fields.sess,
    rcv: fields.rcv,
    bind: fields.bind,
    infl: fields.infl,
    prev: fields.prev,
  };
  return { ...base, sig: encode(sign(privateKey, signingBytesV3(base))) };
}

function toV3(o: Record<string, unknown>): StampV3 {
  return {
    v: 3,
    svc: o.svc as string,
    inst: o.inst as string,
    rid: o.rid as string,
    ts: o.ts as number,
    sess: o.sess as string,
    rcv: o.rcv as string,
    bind: o.bind as string,
    infl: o.infl as string,
    prev: o.prev as string,
    sig: o.sig as string,
  };
}

/** Throws unless value is a non-empty array of well-formed v3 stamps. */
export function parseStampsV3(value: unknown): StampV3[] {
  return nonEmptyArray(value).map((item) => toV3(checkStamp(item)));
}
