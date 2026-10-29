// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode, encode } from "../encoding/b64url.ts";
import { utf8 } from "../crypto/crypto.ts";
import type { StampV1 } from "./stamp.ts";

export function encodeChainV1(stamps: StampV1[]): string {
  const ordered = stamps.map((s) => ({
    svc: s.svc, inst: s.inst, rid: s.rid, ts: s.ts, bind: s.bind, prev: s.prev, sig: s.sig,
  }));
  return encode(utf8(JSON.stringify(ordered)));
}

/** Fails closed: throws on bad base64url, bad JSON, a non-array, or a wrong-typed field. */
export function decodeChainV1(text: string): StampV1[] {
  const value: unknown = JSON.parse(Buffer.from(decode(text)).toString("utf8"));
  if (!Array.isArray(value)) {
    throw new Error("chain must be an array");
  }
  return value.map((item): StampV1 => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error("stamp must be an object");
    }
    const v = item as Record<string, unknown>;
    if (
      typeof v.svc !== "string" || typeof v.inst !== "string" || typeof v.rid !== "string" ||
      typeof v.ts !== "number" || !Number.isFinite(v.ts) ||
      typeof v.bind !== "string" || typeof v.prev !== "string" || typeof v.sig !== "string"
    ) {
      throw new Error("malformed stamp");
    }
    return { svc: v.svc, inst: v.inst, rid: v.rid, ts: v.ts, bind: v.bind, prev: v.prev, sig: v.sig };
  });
}
