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

/** Checks one stamp object's typed fields; returns it as a record. */
function checkStamp(item: unknown, v: 2 | 3, strings: readonly string[]): Record<string, unknown> {
  if (typeof item !== "object" || item === null || Array.isArray(item)) {
    throw new Error("stamp must be an object");
  }
  const o = item as Record<string, unknown>;
  if (o.v !== v || typeof o.ts !== "number" || !Number.isSafeInteger(o.ts)) {
    throw new Error("malformed stamp");
  }
  for (const f of [...strings, "sig"]) {
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
  return o;
}

function nonEmptyArray(value: unknown): unknown[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("stamps must be a non-empty array");
  }
  return value;
}

function toV2(o: Record<string, unknown>): StampV2 {
  return {
    v: 2,
    svc: o.svc as string,
    inst: o.inst as string,
    rid: o.rid as string,
    ts: o.ts as number,
    sess: o.sess as string,
    bind: o.bind as string,
    infl: o.infl as string,
    prev: o.prev as string,
    sig: o.sig as string,
  };
}

/** Throws unless value is a non-empty array of objects with exactly-typed v2 stamp fields. */
export function parseStampsV2(value: unknown): StampV2[] {
  return nonEmptyArray(value).map((item) => toV2(checkStamp(item, 2, V2_STRING_FIELDS)));
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

/** A stamp as recorded: v2 (legacy) or v3. */
export type RecordedStamp = StampV2 | StampV3;

const V3_STRING_FIELDS = ["svc", "inst", "rid", "sess", "rcv", "bind", "infl", "prev"] as const;

/** The exact bytes covered by a v3 stamp's signature; throws if any string field contains the delimiter or a lone surrogate. */
export function signingBytesV3(s: Omit<StampV3, "sig">): Uint8Array {
  for (const f of V3_STRING_FIELDS) {
    if (s[f].includes("|")) {
      throw new Error(`stamp field ${f} must not contain '|'`);
    }
    if (LONE_SURROGATE.test(s[f])) {
      throw new Error(`stamp field ${f} must not contain a lone surrogate`);
    }
  }
  return utf8(`3|${s.svc}|${s.inst}|${s.rid}|${s.ts}|${s.sess}|${s.rcv}|${s.bind}|${s.infl}|${s.prev}`);
}

export function signStampV3(fields: Omit<StampV3, "sig" | "v">, privateKey: string): StampV3 {
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
  const { v: _v, sig, ...rest } = toV2(o);
  return { v: 3, svc: rest.svc, inst: rest.inst, rid: rest.rid, ts: rest.ts, sess: rest.sess, rcv: o.rcv as string, bind: rest.bind, infl: rest.infl, prev: rest.prev, sig };
}

/** Throws unless value is a non-empty array of well-formed v3 stamps. */
export function parseStampsV3(value: unknown): StampV3[] {
  return nonEmptyArray(value).map((item) => toV3(checkStamp(item, 3, V3_STRING_FIELDS)));
}

/** Reads a recorded chain: all v2 (legacy) or all v3; throws on a mixed, empty or malformed chain. */
export function parseRecordedStamps(value: unknown): { stamps: RecordedStamp[]; legacy: boolean } {
  const items = nonEmptyArray(value);
  const first = items[0];
  const v = typeof first === "object" && first !== null ? (first as Record<string, unknown>).v : undefined;
  if (v === 2) {
    return { stamps: parseStampsV2(items), legacy: true };
  }
  if (v === 3) {
    return { stamps: parseStampsV3(items), legacy: false };
  }
  throw new Error("malformed stamp");
}

/** The exact bytes covered by a recorded stamp's signature, by its version. */
export function signingBytes(s: RecordedStamp): Uint8Array {
  return s.v === 3 ? signingBytesV3(s) : signingBytesV2(s);
}
