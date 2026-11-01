// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// What Paztport's JSON readers and writers agree on (spec wire.md, JSON): the limits, the error, and which code
// points are noncharacters. json.ts, json-file.ts and jcs.ts import it, and it imports none of them.

import { isWellFormed } from "../crypto/crypto.ts";

/** The reader step, or the writer, that refused. */
export type JsonStep = "size" | "parse" | "canonical" | "write";

export class MalformedJson extends Error {
  readonly step: JsonStep;
  constructor(step: JsonStep, message: string) {
    super(`json ${step}: ${message}`);
    this.name = "MalformedJson";
    this.step = step;
  }
}

/** At a limit a value is read, and one past it refused. `tokenText` is the base64url length of `wireBytes`. */
export const JSON_LIMITS = { wireBytes: 262144, tokenText: 349526, fileBytes: 1048576, depth: 32 } as const;

/** U+FDD0 to U+FDEF, and every code point whose last four hex digits are FFFE or FFFF (RFC 7493 §2.1). */
export function noncharacter(cp: number): boolean {
  return (cp >= 0xfdd0 && cp <= 0xfdef) || (cp & 0xfffe) === 0xfffe;
}

/** True when `s` holds no lone surrogate and no noncharacter: text a Paztport object's string field may carry. */
export function isProtocolText(s: string): boolean {
  if (!isWellFormed(s)) return false;
  for (const ch of s) {
    if (noncharacter(ch.codePointAt(0)!)) return false;
  }
  return true;
}
