// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { concat, sign, utf8 } from "../crypto/crypto.ts";
import { writeWire } from "../encoding/jcs.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { isProtocolText } from "../encoding/json-rules.ts";
import { array, exactly, int, object, str } from "../internal/fields.ts";

/** The stamp version this SDK signs and reads (spec wire.md, Stamps): the one place the number is written. */
export const STAMP_VERSION = 4;

/** A stamp (spec wire.md, Stamps): one hop's signature over what it sent, linked to the stamp before it. */
export type Stamp = {
  v: 4;
  /** The signing service, whose key the verifier looks up by this name. */
  svc: string;
  /** The signer's instance, as the signer reports it: signed, but only the signer vouches for it. */
  inst: string;
  /** The request id, minted at the origin and carried unchanged by every stamp. */
  rid: string;
  /** When this stamp was signed, in ms since the Unix epoch. */
  ts: number;
  /** The session id, or "" for a chain with no session. */
  sess: string;
  /**
   * The receiver this stamp was signed for: the next stamp's svc, or for the last stamp the chain's receiver. Over
   * HTTP it may name the operation invoked there, as `<service>#<operation>`.
   */
  rcv: string;
  /** The binding of what this hop sent (spec wire.md, Bindings). */
  bind: string;
  /** The commitment to this stamp's block, the claims its signer attaches (`commitBlock`); "" for the empty block. */
  ext: string;
  /** The previous stamp's sig, exactly as written, or "" at the origin. */
  prev: string;
  /** The base64url Ed25519 signature, by svc's key, over the signed bytes (signingBytes). */
  sig: string;
};

const STRING_FIELDS = ["svc", "inst", "rid", "sess", "rcv", "bind", "ext", "prev"] as const;

/** The stamp's domain prefix (spec wire.md, Encodings), so no other signed message reads as a stamp. */
const PREFIX = utf8("paztport-stamp\n");

/**
 * The exact bytes covered by a stamp's signature: its domain prefix, then the canonical bytes of its ten members other
 * than `sig` (spec wire.md, Fields and signed bytes). A `sig` among `s`'s members is left out. Throws naming the field
 * that holds a lone surrogate or a noncharacter, which no reader takes, and MalformedJson for a `ts` that is not a
 * protocol integer.
 */
export function signingBytes(s: Omit<Stamp, "sig">): Uint8Array {
  for (const f of STRING_FIELDS) {
    if (!isProtocolText(s[f])) {
      throw new Error(`stamp field ${f} must not contain a lone surrogate or a noncharacter`);
    }
  }
  const members = {
    v: s.v, svc: s.svc, inst: s.inst, rid: s.rid, ts: s.ts, sess: s.sess, rcv: s.rcv, bind: s.bind, ext: s.ext,
    prev: s.prev,
  };
  return concat(PREFIX, writeWire(members));
}

/**
 * Signs a stamp, the one every live producer makes; throws if a field holds a lone surrogate or a noncharacter, or
 * `ts` is outside [0, 2^53 − 1].
 */
export function signStamp(fields: Omit<Stamp, "sig" | "v">, privateKey: string): Stamp {
  if (!Number.isSafeInteger(fields.ts) || fields.ts < 0) {
    throw new Error("stamp ts must be an integer in [0, 2^53 - 1]");
  }
  const base: Omit<Stamp, "sig"> = {
    v: STAMP_VERSION,
    svc: fields.svc,
    inst: fields.inst,
    rid: fields.rid,
    ts: fields.ts,
    sess: fields.sess,
    rcv: fields.rcv,
    bind: fields.bind,
    ext: fields.ext,
    prev: fields.prev,
  };
  return { ...base, sig: encode(sign(privateKey, signingBytes(base))) };
}

const MEMBERS = ["v", "svc", "inst", "rid", "ts", "sess", "rcv", "bind", "ext", "prev", "sig"];

/** One stamp by the stamp's schema; throws naming the member it refuses. */
function stampOf(item: JsonValue): Stamp {
  const o = object(item);
  exactly(o, MEMBERS);
  if (int(o, "v") !== STAMP_VERSION) {
    throw new Error(`member v is not ${STAMP_VERSION}`);
  }
  const sig = str(o, "sig");
  try {
    decode(sig);
  } catch {
    throw new Error("member sig is not canonical base64url");
  }
  return {
    v: STAMP_VERSION,
    svc: str(o, "svc"),
    inst: str(o, "inst"),
    rid: str(o, "rid"),
    ts: int(o, "ts"),
    sess: str(o, "sess"),
    rcv: str(o, "rcv"),
    bind: str(o, "bind"),
    ext: str(o, "ext"),
    prev: str(o, "prev"),
    sig,
  };
}

/**
 * The stamps of a chain the reader has read: a non-empty array of stamps, each with exactly the stamp's members,
 * `v` the STAMP_VERSION, `ts` a protocol integer, the rest strings and `sig` canonical base64url. Throws an Error
 * naming what it refuses. Internal: index.ts exports readChain.
 */
export function chainOf(value: JsonValue): Stamp[] {
  const items = array(value);
  if (items.length === 0) {
    throw new Error("a chain with no stamps");
  }
  return items.map(stampOf);
}

/**
 * Reads a chain from its token: MalformedJson for bytes that do not read, an Error naming the member for a stamp the
 * schema refuses.
 */
export function readChain(token: string): Stamp[] {
  return chainOf(readToken(token));
}
