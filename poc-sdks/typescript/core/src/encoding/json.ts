// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Reads Paztport's own objects from bytes (spec wire.md, JSON): the size limit, the strict parse, and for wire bytes
// the canonical-bytes check. The schema, step 4, belongs to each object's own module.

import { decode } from "./b64url.ts";
import { noncharacter, writeWire } from "./jcs.ts";

/** A value as the reader gives it: every number an integer in [0, 2^53 − 1], every object null-prototyped. */
export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = { readonly [name: string]: JsonValue };

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

/** Wire bytes: within the wire limit, one JSON value, and exactly that value's canonical bytes. */
export function readWireBytes(bytes: Uint8Array): JsonValue {
  checkSize(bytes, JSON_LIMITS.wireBytes);
  const value = new Parser(bytes).document();
  const canonical = writeWire(value);
  if (canonical.length !== bytes.length || canonical.some((b, i) => b !== bytes[i])) {
    throw new MalformedJson("canonical", "the bytes are not the canonical bytes of the value they hold");
  }
  return value;
}

/** A base64url token: its text length first, so a long one is never decoded, then its bytes as wire bytes. */
export function readToken(token: string): JsonValue {
  if (token.length > JSON_LIMITS.tokenText) {
    throw new MalformedJson("size", `a token of ${token.length} characters, over ${JSON_LIMITS.tokenText}`);
  }
  let bytes: Uint8Array;
  try {
    bytes = decode(token);
  } catch {
    throw new MalformedJson("parse", "the token is not base64url");
  }
  return readWireBytes(bytes);
}

/** A file: within the file limit and one JSON value, in any member order, whitespace and escapes. */
export function readFile(bytes: Uint8Array): JsonValue {
  checkSize(bytes, JSON_LIMITS.fileBytes);
  return new Parser(bytes).document();
}

function checkSize(bytes: Uint8Array, limit: number): void {
  if (bytes.length > limit) throw new MalformedJson("size", `${bytes.length} bytes, over ${limit}`);
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
/** The character each short escape stands for, by the byte after its backslash. */
const ESCAPED: Record<number, number> = {
  0x22: 0x22,
  0x5c: 0x5c,
  0x2f: 0x2f,
  0x62: 0x08,
  0x66: 0x0c,
  0x6e: 0x0a,
  0x72: 0x0d,
  0x74: 0x09,
};
const MAX_INTEGER = "9007199254740991";

const isDigit = (b: number | undefined): boolean => b !== undefined && b >= 0x30 && b <= 0x39;

/**
 * One pass over the bytes by RFC 8259's grammar, within RFC 7493: strict UTF-8 (RFC 3629), no lone surrogate, no
 * noncharacter, no repeated name, and protocol integers only. Each check runs before the value it guards is built,
 * and the depth before each descent, so the recursion is never deeper than the depth limit.
 */
class Parser {
  private readonly bytes: Uint8Array;
  private pos = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  document(): JsonValue {
    this.whitespace();
    const value = this.value(0);
    this.whitespace();
    if (this.pos !== this.bytes.length) this.fail("bytes after the value");
    return value;
  }

  private fail(why: string): never {
    throw new MalformedJson("parse", `${why} at byte ${this.pos}`);
  }

  private whitespace(): void {
    for (;;) {
      const b = this.bytes[this.pos];
      if (b !== 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) return;
      this.pos++;
    }
  }

  /** `depth` is how many arrays and objects hold this value. */
  private value(depth: number): JsonValue {
    const b = this.bytes[this.pos];
    if (b === 0x7b) return this.object(depth);
    if (b === 0x5b) return this.array(depth);
    if (b === QUOTE) return this.string();
    if (b === 0x74) return this.literal("true", true);
    if (b === 0x66) return this.literal("false", false);
    if (b === 0x6e) return this.literal("null", null);
    if (b === 0x2d) this.fail("a negative number, which is not a protocol integer");
    if (isDigit(b)) return this.integer();
    return this.fail(b === undefined ? "the end of the bytes where a value belongs" : "no value");
  }

  private descend(depth: number): void {
    if (depth === JSON_LIMITS.depth) this.fail(`an array or object nested deeper than ${JSON_LIMITS.depth} levels`);
    this.pos++;
    this.whitespace();
  }

  private expect(b: number, what: string): void {
    if (this.bytes[this.pos] !== b) this.fail(`no ${what}`);
    this.pos++;
  }

  private array(depth: number): JsonValue[] {
    this.descend(depth);
    const out: JsonValue[] = [];
    if (this.bytes[this.pos] === 0x5d) {
      this.pos++;
      return out;
    }
    for (;;) {
      out.push(this.value(depth + 1));
      this.whitespace();
      if (this.bytes[this.pos] === 0x5d) {
        this.pos++;
        return out;
      }
      this.expect(0x2c, "comma or ] after an element");
      this.whitespace();
    }
  }

  private object(depth: number): JsonObject {
    this.descend(depth);
    // Null-prototyped, so a name such as __proto__ is an ordinary own member and no name reaches an inherited one.
    const out: Record<string, JsonValue> = Object.create(null);
    if (this.bytes[this.pos] === 0x7d) {
      this.pos++;
      return out;
    }
    for (;;) {
      if (this.bytes[this.pos] !== QUOTE) this.fail("no member name");
      const name = this.string();
      // Compared after unescaping, so "\u0061" and "a" are one name (RFC 7493 §2.3).
      if (Object.hasOwn(out, name)) this.fail("a repeated member name");
      this.whitespace();
      this.expect(0x3a, "colon after a member name");
      this.whitespace();
      out[name] = this.value(depth + 1);
      this.whitespace();
      if (this.bytes[this.pos] === 0x7d) {
        this.pos++;
        return out;
      }
      this.expect(0x2c, "comma or } after a member");
      this.whitespace();
    }
  }

  private literal<T>(text: string, value: T): T {
    for (let i = 0; i < text.length; i++) {
      if (this.bytes[this.pos + i] !== text.charCodeAt(i)) this.fail(`no ${text}`);
    }
    this.pos += text.length;
    return value;
  }

  /** A protocol integer, decided from its text: refused at a seventeenth digit, a fraction or an exponent. */
  private integer(): number {
    const start = this.pos;
    if (this.bytes[this.pos] === 0x30) {
      this.pos++;
      if (isDigit(this.bytes[this.pos])) this.fail("a leading zero");
    } else {
      while (isDigit(this.bytes[this.pos])) {
        if (this.pos - start === 16) this.fail("a number of more than 16 digits");
        this.pos++;
      }
    }
    const next = this.bytes[this.pos];
    if (next === 0x2e || next === 0x65 || next === 0x45) {
      this.fail("a fraction or exponent, which is not a protocol integer");
    }
    const digits = String.fromCharCode(...this.bytes.subarray(start, this.pos));
    // Equal lengths of digits compare as their values do.
    if (digits.length === MAX_INTEGER.length && digits > MAX_INTEGER) this.fail("an integer over 2^53 - 1");
    return Number(digits);
  }

  private string(): string {
    this.pos++;
    let out = "";
    const pending: number[] = [];
    for (;;) {
      const b = this.bytes[this.pos];
      if (b === undefined) this.fail("a string with no closing quote");
      if (b === QUOTE) break;
      let cp: number;
      if (b === BACKSLASH) cp = this.escape();
      else if (b < 0x20) this.fail("a raw control character in a string");
      else if (b < 0x80) {
        cp = b;
        this.pos++;
      } else cp = this.utf8(b);
      if (noncharacter(cp)) this.fail(`the noncharacter U+${cp.toString(16).toUpperCase()}`);
      pending.push(cp);
      // Flushed in chunks, to keep each call's argument list short.
      if (pending.length === 4096) {
        out += String.fromCodePoint(...pending);
        pending.length = 0;
      }
    }
    this.pos++;
    return out + String.fromCodePoint(...pending);
  }

  /** An escape RFC 8259 defines, with a surrogate pair as one code point and a lone surrogate refused. */
  private escape(): number {
    const b = this.bytes[this.pos + 1];
    if (b !== 0x75) {
      const cp = b === undefined ? undefined : ESCAPED[b];
      if (cp === undefined) this.fail("an escape RFC 8259 does not define");
      this.pos += 2;
      return cp;
    }
    const high = this.hex4();
    if (high >= 0xdc00 && high <= 0xdfff) this.fail("a lone low surrogate");
    if (high < 0xd800 || high > 0xdbff) return high;
    if (this.bytes[this.pos] !== BACKSLASH || this.bytes[this.pos + 1] !== 0x75) this.fail("a lone high surrogate");
    const low = this.hex4();
    if (low < 0xdc00 || low > 0xdfff) this.fail("a lone high surrogate");
    return 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00);
  }

  /** The four hex digits after a backslash and u, in either case. */
  private hex4(): number {
    let unit = 0;
    for (let i = 2; i < 6; i++) {
      const b = this.bytes[this.pos + i];
      let digit: number;
      if (b === undefined) digit = -1;
      else if (b >= 0x30 && b <= 0x39) digit = b - 0x30;
      else if (b >= 0x61 && b <= 0x66) digit = b - 0x61 + 10;
      else if (b >= 0x41 && b <= 0x46) digit = b - 0x41 + 10;
      else digit = -1;
      if (digit < 0) this.fail("a \\u escape without four hex digits");
      unit = unit * 16 + digit;
    }
    this.pos += 6;
    return unit;
  }

  /**
   * One UTF-8 sequence by RFC 3629's table. The second byte's range rules out overlong forms (E0, F0), surrogates
   * (ED) and code points above U+10FFFF (F4); C0, C1 and F5 to FF start no sequence.
   */
  private utf8(lead: number): number {
    let more: number, low = 0x80, high = 0xbf, cp: number;
    if (lead >= 0xc2 && lead <= 0xdf) {
      more = 1;
      cp = lead & 0x1f;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      more = 2;
      cp = lead & 0x0f;
      if (lead === 0xe0) low = 0xa0;
      if (lead === 0xed) high = 0x9f;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      more = 3;
      cp = lead & 0x07;
      if (lead === 0xf0) low = 0x90;
      if (lead === 0xf4) high = 0x8f;
    } else {
      return this.fail(`the byte 0x${lead.toString(16)}, which starts no UTF-8 sequence`);
    }
    for (let i = 1; i <= more; i++) {
      const b = this.bytes[this.pos + i];
      if (b === undefined || b < low || b > high) this.fail("an invalid or cut-short UTF-8 sequence");
      cp = (cp << 6) | (b & 0x3f);
      low = 0x80;
      high = 0xbf;
    }
    this.pos += more + 1;
    return cp;
  }
}
