// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { sign, utf8 } from "../crypto/crypto.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { isProtocolText } from "../encoding/json-rules.ts";
import { array, exactly, int, object, str } from "../internal/fields.ts";

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

const MEMBERS = ["v", "svc", "inst", "rid", "ts", "sess", "rcv", "bind", "infl", "prev", "sig"];

/** One stamp by the stamp's schema; throws naming the member it refuses. */
function stampOf(item: JsonValue): StampV3 {
  const o = object(item);
  exactly(o, MEMBERS);
  if (int(o, "v") !== 3) {
    throw new Error("member v is not 3");
  }
  const sig = str(o, "sig");
  decode(sig);
  return {
    v: 3,
    svc: str(o, "svc"),
    inst: str(o, "inst"),
    rid: str(o, "rid"),
    ts: int(o, "ts"),
    sess: str(o, "sess"),
    rcv: str(o, "rcv"),
    bind: str(o, "bind"),
    infl: str(o, "infl"),
    prev: str(o, "prev"),
    sig,
  };
}

/**
 * The stamps of a chain the reader has read: a non-empty array of stamps, each with exactly the stamp's members,
 * `v` 3, `ts` a protocol integer, the rest strings and `sig` canonical base64url. Throws an Error naming what it
 * refuses. Internal: index.ts exports readChain.
 */
export function chainOf(value: JsonValue): StampV3[] {
  const items = array(value);
  if (items.length === 0) {
    throw new Error("a chain with no stamps");
  }
  return items.map(stampOf);
}

/** Reads a chain from its token: MalformedJson for bytes that do not read, an Error naming the member for a stamp the schema refuses. */
export function readChain(token: string): StampV3[] {
  return chainOf(readToken(token));
}
