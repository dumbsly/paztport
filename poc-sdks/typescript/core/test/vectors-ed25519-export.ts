// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds spec/vectors/ed25519.json, the Ed25519 vectors for the signature rule (spec wire.md, Signatures); run with
// `--write` from poc-sdks/typescript to write the file. The cases sit where Ed25519 libraries disagree: S at or above
// the group order, non-canonical encodings, points of small order, and the cofactor. Every case is crafted, and every
// answer worked out, by RFC 8032 arithmetic written out below with BigInt, so no implementation confirms its own
// answers: this file imports nothing but node: modules.

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ED25519_JSON = new URL("../../../spec/vectors/ed25519.json", import.meta.url);

// --- The field and the curve (RFC 8032 §5.1) ---

const p = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function mod(x: bigint, m: bigint = p): bigint {
  const r = x % m;
  return r < 0n ? r + m : r;
}

function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
  }
  return result;
}

/** The inverse by Fermat: p is prime. */
function invert(x: bigint): bigint {
  return power(x, p - 2n);
}

const d = mod(-121665n * invert(121666n));
const SQRT_M1 = power(2n, (p - 1n) / 4n);

/** A point in extended coordinates (RFC 8032 §5.1.4): x = X/Z, y = Y/Z, x·y = T/Z. */
type Point = { X: bigint; Y: bigint; Z: bigint; T: bigint };

const IDENTITY: Point = { X: 0n, Y: 1n, Z: 1n, T: 0n };

/** RFC 8032 §5.1.4's addition. It is complete (d is not a square), so it also doubles and handles points of small order. */
function add(P: Point, Q: Point): Point {
  const A = mod((P.Y - P.X) * (Q.Y - Q.X));
  const B = mod((P.Y + P.X) * (Q.Y + Q.X));
  const C = mod(P.T * 2n * d * Q.T);
  const D = mod(P.Z * 2n * Q.Z);
  const E = B - A;
  const F = D - C;
  const G = D + C;
  const H = B + A;
  return { X: mod(E * F), Y: mod(G * H), Z: mod(F * G), T: mod(E * H) };
}

function multiply(n: bigint, P: Point): Point {
  let result = IDENTITY;
  let addend = P;
  for (let e = n; e > 0n; e >>= 1n) {
    if (e & 1n) result = add(result, addend);
    addend = add(addend, addend);
  }
  return result;
}

function equal(P: Point, Q: Point): boolean {
  return mod(P.X * Q.Z - Q.X * P.Z) === 0n && mod(P.Y * Q.Z - Q.Y * P.Z) === 0n;
}

function fromAffine(x: bigint, y: bigint): Point {
  return { X: x, Y: y, Z: 1n, T: mod(x * y) };
}

/** The smallest of 1, 2, 4 and 8 that takes `P` to the identity; only meaningful for a point of small order. */
function smallOrder(P: Point): bigint {
  for (const n of [1n, 2n, 4n, 8n]) if (equal(multiply(n, P), IDENTITY)) return n;
  throw new Error("not a point of small order");
}

// --- Encoding (RFC 8032 §5.1.2, §5.1.3) ---

function littleEndian(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function bytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((n >> BigInt(8 * i)) & 0xffn);
  return out;
}

/** y little-endian, with x's low bit in the top bit of the last byte. */
function encodeXY(x: bigint, y: bigint): Uint8Array {
  return bytes32(y | ((x & 1n) << 255n));
}

function encode(P: Point): Uint8Array {
  const zInverse = invert(P.Z);
  return encodeXY(mod(P.X * zInverse), mod(P.Y * zInverse));
}

/** The bytes as written with the top bit cleared: the value rules 3 and 4 test. */
function yOf(encoding: Uint8Array): bigint {
  return littleEndian(encoding) & ((1n << 255n) - 1n);
}

/** The x for `y` with the low bit `sign`, or null when (y² − 1)/(d·y² + 1) is not a square or x = 0 with sign 1. */
function recoverX(y: bigint, sign: bigint): bigint | null {
  const u = mod(y * y - 1n);
  const v = mod(d * y * y + 1n);
  // x = (u/v)^((p+3)/8), computed as u·v³·(u·v⁷)^((p−5)/8) so it needs no inversion.
  let x = mod(u * power(v, 3n) * power(u * power(v, 7n), (p - 5n) / 8n));
  const vxx = mod(v * x * x);
  if (vxx === u) {
    // x is a square root
  } else if (vxx === mod(-u)) {
    x = mod(x * SQRT_M1);
  } else {
    return null;
  }
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = p - x;
  return x;
}

/**
 * Decodes by RFC 8032 §5.1.3: null for a y at or above p, for a y on no curve point, and for x = 0 with the sign bit set.
 * `lenient` reads y modulo p and takes x = 0 whatever the sign bit, as a library that skips those checks does: the
 * generator uses it only to check that a non-canonical case would be valid but for rule 3 or 4.
 */
function decode(encoding: Uint8Array, lenient = false): Point | null {
  if (encoding.length !== 32) return null;
  let y = yOf(encoding);
  const sign = BigInt(encoding[31] >> 7);
  if (y >= p) {
    if (!lenient) return null;
    y -= p;
  }
  const x = recoverX(y, sign) ?? (lenient ? recoverX(y, 0n) : null);
  return x === null ? null : fromAffine(x, y);
}

/** B, the base point: y = 4/5, x even. Named BASE because RFC 8032's addition uses B for one of its terms. */
const BASE = fromAffine(recoverX(mod(4n * invert(5n)), 0n)!, mod(4n * invert(5n)));

/** T, a point of order 8: [L]P for the first P, by ascending y with x even, whose [L]P has order 8. */
const T = ((): Point => {
  for (let y = 0n; ; y++) {
    const x = recoverX(y, 0n);
    if (x === null) continue;
    const Q = multiply(L, fromAffine(x, y));
    if (!equal(multiply(4n, Q), IDENTITY) && equal(multiply(8n, Q), IDENTITY)) return Q;
  }
})();

/** The y8 of the case names: the y of T. */
const Y8 = yOf(encode(T));

/** The y of every point of small order: the identity, order 2, order 4 and order 8. Ascending, as the file lists them. */
const SMALL_ORDER_Y = [1n, p - 1n, 0n, Y8, p - Y8].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

// --- Keys and signatures (RFC 8032 §5.1.5 to §5.1.7) ---

function sha512(...parts: Uint8Array[]): Uint8Array {
  const hash = createHash("sha512");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}

function sha512ModL(...parts: Uint8Array[]): bigint {
  return mod(littleEndian(sha512(...parts)), L);
}

function utf8(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "utf8"));
}

const SPKI_PREFIX = Uint8Array.from(Buffer.from("302a300506032b6570032100", "hex"));

function spki(a: Uint8Array): Uint8Array {
  return Uint8Array.from([...SPKI_PREFIX, ...a]);
}

type Key = { a: bigint; prefix: Uint8Array; A: Uint8Array };

/** RFC 8032 §5.1.5. */
function keyFromSeed(seed: Uint8Array): Key {
  const h = sha512(seed);
  const s = h.slice(0, 32);
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  const a = littleEndian(s);
  return { a, prefix: h.slice(32), A: encode(multiply(a, BASE)) };
}

/** RFC 8032 §5.1.6. */
function sign(key: Key, message: Uint8Array): Uint8Array {
  const r = sha512ModL(key.prefix, message);
  const R = encode(multiply(r, BASE));
  const k = sha512ModL(R, key.A, message);
  return Uint8Array.from([...R, ...bytes32(mod(r + k * key.a, L))]);
}

type Equation = "cofactorless" | "cofactored";

/** Rule 5's equation, [S]B = R + [k]A, or with both sides multiplied by 8; k is over R and A as written. */
function equationHolds(A: Uint8Array, signature: Uint8Array, message: Uint8Array, equation: Equation, lenient = false): boolean {
  const Rbytes = signature.subarray(0, 32);
  const Rpoint = decode(Rbytes, lenient);
  const Apoint = decode(A, lenient);
  if (Rpoint === null || Apoint === null) return false;
  const k = sha512ModL(Rbytes, A, message);
  const left = multiply(littleEndian(signature.subarray(32)), BASE);
  const right = add(Rpoint, multiply(k, Apoint));
  return equation === "cofactorless" ? equal(left, right) : equal(multiply(8n, left), multiply(8n, right));
}

/** Rules 1 to 4 of the signature rule (spec wire.md, Signatures): the checks in front of the library. */
function encodingsHold(key: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64 || key.length !== 44) return false;
  if (!SPKI_PREFIX.every((byte, i) => key[i] === byte)) return false;
  if (littleEndian(signature.subarray(32)) >= L) return false;
  for (const point of [signature.subarray(0, 32), key.subarray(12)]) {
    const y = yOf(point);
    if (y >= p || SMALL_ORDER_Y.includes(y)) return false;
  }
  return true;
}

/** The whole rule: rules 1 to 4, then rule 5 with no multiplication by the cofactor. */
function verifyStrict(key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  return encodingsHold(key, signature) && equationHolds(key.subarray(12), signature, message, "cofactorless");
}

// --- The cases ---

const HONEST = keyFromSeed(new Uint8Array(createHash("sha256").update("paztport-ed25519-vector-key:signer").digest()));
const MESSAGE = utf8("paztport ed25519 vector");
const HONEST_SIGNATURE = sign(HONEST, MESSAGE);

/** The fixed nonce of the crafted cases, whose S is r, or r + k·a, rather than one the honest key would choose. */
const r = sha512ModL(utf8("paztport-ed25519-vector-nonce"));
const R_r = encode(multiply(r, BASE));

/**
 * The first of "m0", "m1", … whose k, over R and A as written, satisfies `accept`, which also sees the 64-byte digest
 * before it is reduced mod L.
 */
function messageWhere(R: Uint8Array, A: Uint8Array, accept: (k: bigint, digest: bigint) => boolean): Uint8Array {
  for (let i = 0; ; i++) {
    const message = utf8("m" + i);
    const digest = littleEndian(sha512(R, A, message));
    if (accept(mod(digest, L), digest)) return message;
  }
}

/** R = [r]B and S = r, over the first message whose k is a multiple of A's order, so [k]A is the identity and the equation holds. */
function signedBySmallOrder(A: Uint8Array): { message: Uint8Array; signature: Uint8Array } {
  const order = smallOrder(decode(A, true)!);
  const message = messageWhere(R_r, A, (k) => k % order === 0n);
  return { message, signature: Uint8Array.from([...R_r, ...bytes32(r)]) };
}

/** R as given and S = k·a, so [S]B = [k]A: the equation holds when R is the identity, and only cofactored when R has order 8. */
function signedWithR(R: Uint8Array): Uint8Array {
  const k = sha512ModL(R, HONEST.A, MESSAGE);
  return Uint8Array.from([...R, ...bytes32(mod(k * HONEST.a, L))]);
}

/** The small-order point with y `y` and x's low bit `sign`, as its canonical encoding. */
function smallPoint(y: bigint, sign: bigint): Uint8Array {
  return encodeXY(recoverX(y, sign)!, y);
}

/** `encoding` with the sign bit set: for a point with x = 0, the second, refused encoding of it. */
function withSignBit(encoding: Uint8Array): Uint8Array {
  const out = Uint8Array.from(encoding);
  out[31] |= 0x80;
  return out;
}

type Built = {
  name: string;
  key: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
  valid: boolean;
  /** For a refused case meant to be refused by rules 1 to 4 alone: the equation that holds when the encodings are read leniently. */
  holds?: Equation;
  /** For a key refused by rule 1 alone: the 32-byte key its bytes carry, which with the signature passes rules 2 to 5. */
  wraps?: Uint8Array;
  /** For a refused case that passes rules 1 to 4, so only the library's decoding or its equation can refuse it. */
  reachesTheLibrary?: true;
  /**
   * For the case that pins k reduced mod L before the multiplication: its k is a multiple of 8 and its unreduced digest
   * is not, so with A's small-order part the equation holds for the one and fails for the other.
   */
  pinsReducedK?: true;
};

function smallOrderKeyCase(name: string, A: Uint8Array): Built {
  return { name, key: spki(A), ...signedBySmallOrder(A), valid: false, holds: "cofactorless" };
}

function buildCases(): Built[] {
  const honest = (name: string, message: Uint8Array, signature: Uint8Array, valid: boolean, holds?: Equation): Built => ({
    name,
    key: spki(HONEST.A),
    message,
    signature,
    valid,
    ...(holds === undefined ? {} : { holds }),
  });
  const S = littleEndian(HONEST_SIGNATURE.subarray(32));
  const topBitSet = Uint8Array.from(HONEST_SIGNATURE);
  topBitSet[63] |= 0x80;

  const identity = bytes32(1n);
  const order2 = bytes32(p - 1n);
  const order4 = (sign: bigint): Uint8Array => smallPoint(0n, sign);
  const order8 = (y: bigint, sign: bigint): Uint8Array => smallPoint(y, sign);

  // A = [a]B + T, which has order 8L: [k]A = [k·a]B + [k]T, so the equation holds only when k is a multiple of 8.
  const mixedA = encode(add(multiply(HONEST.a, BASE), T));
  const mixed = (accept: (k: bigint, digest: bigint) => boolean): { message: Uint8Array; signature: Uint8Array } => {
    const message = messageWhere(R_r, mixedA, accept);
    const k = sha512ModL(R_r, mixedA, message);
    return { message, signature: Uint8Array.from([...R_r, ...bytes32(mod(r + k * HONEST.a, L))]) };
  };

  // R = [r]B + T: [S]B differs from R + [k]A by T, which multiplying by 8 removes.
  const mixedR = encode(add(multiply(r, BASE), T));
  const kMixedR = sha512ModL(mixedR, HONEST.A, MESSAGE);

  // The smallest y ≥ 2 on no curve point (0 and 1 are on the curve).
  let offCurveY = 2n;
  while (recoverX(offCurveY, 0n) !== null) offCurveY++;

  return [
    honest("a signature by the key", MESSAGE, HONEST_SIGNATURE, true),
    honest("the empty message", new Uint8Array(), sign(HONEST, new Uint8Array()), true),
    honest("a signature over another message", MESSAGE, sign(HONEST, utf8("another message")), false),
    honest("S plus the group order", MESSAGE, Uint8Array.from([...HONEST_SIGNATURE.subarray(0, 32), ...bytes32(S + L)]), false, "cofactorless"),
    honest("S with its top bit set", MESSAGE, topBitSet, false),
    honest("R the identity, made with the key", MESSAGE, signedWithR(identity), false, "cofactorless"),
    honest("R the identity, written with y = p + 1", MESSAGE, signedWithR(bytes32(p + 1n)), false, "cofactorless"),
    honest("R of order 8, S made for the cofactored equation", MESSAGE, signedWithR(encode(T)), false, "cofactored"),
    smallOrderKeyCase("A the identity", identity),
    smallOrderKeyCase("A of order 2", order2),
    smallOrderKeyCase("A of order 4, x sign 0", order4(0n)),
    smallOrderKeyCase("A of order 4, x sign 1", order4(1n)),
    smallOrderKeyCase("A of order 8, y8, x sign 0", order8(Y8, 0n)),
    smallOrderKeyCase("A of order 8, y8, x sign 1", order8(Y8, 1n)),
    smallOrderKeyCase("A of order 8, p - y8, x sign 0", order8(p - Y8, 0n)),
    smallOrderKeyCase("A of order 8, p - y8, x sign 1", order8(p - Y8, 1n)),
    smallOrderKeyCase("A the identity with the sign bit set", withSignBit(identity)),
    smallOrderKeyCase("A of order 2 with the sign bit set", withSignBit(order2)),
    smallOrderKeyCase("A the identity, written with y = p + 1", bytes32(p + 1n)),
    smallOrderKeyCase("A of order 4, written with y = p", bytes32(p)),
    {
      name: "A with a small-order part, k not a multiple of 8",
      key: spki(mixedA),
      ...mixed((k) => k % 8n !== 0n),
      valid: false,
      holds: "cofactored",
      reachesTheLibrary: true,
    },
    {
      ...honest(
        "R with a small-order part, S made for the cofactored equation",
        MESSAGE,
        Uint8Array.from([...mixedR, ...bytes32(mod(r + kMixedR * HONEST.a, L))]),
        false,
        "cofactored",
      ),
      reachesTheLibrary: true,
    },
    // RFC 8032 §5.1.7 multiplies A by the digest as it is; the rule reduces it mod L first. The two differ only on a
    // key with a small-order part, and only when one is a multiple of 8 and the other is not, as here.
    {
      name: "A with a small-order part, k a multiple of 8",
      key: spki(mixedA),
      ...mixed((k, digest) => k % 8n === 0n && digest % 8n !== 0n),
      valid: true,
      pinsReducedK: true,
    },
    {
      name: "A whose y is on no curve point",
      key: spki(bytes32(offCurveY)),
      message: MESSAGE,
      signature: Uint8Array.from([...R_r, ...bytes32(r)]),
      valid: false,
      reachesTheLibrary: true,
    },
    honest("a signature of 63 bytes", MESSAGE, HONEST_SIGNATURE.subarray(0, 63), false),
    honest("a signature of 65 bytes", MESSAGE, Uint8Array.from([...HONEST_SIGNATURE, 0]), false),
    { name: "a key of 31 bytes", key: Uint8Array.from([...SPKI_PREFIX, ...HONEST.A.subarray(0, 31)]), message: MESSAGE, signature: HONEST_SIGNATURE, valid: false },
    {
      name: "a key under the X25519 identifier",
      key: Uint8Array.from([...SPKI_PREFIX.subarray(0, 8), 0x6e, ...SPKI_PREFIX.subarray(9), ...HONEST.A]),
      message: MESSAGE,
      signature: HONEST_SIGNATURE,
      valid: false,
    },
    // DER allows the long form of a length only where the short form cannot hold it, so this is not the Ed25519 SPKI;
    // a library that decodes the key and re-encodes it canonically gets the 44 bytes back, and would otherwise accept it.
    {
      name: "a key whose SPKI length is written in long form",
      key: Uint8Array.from([0x30, 0x81, 0x2a, ...spki(HONEST.A).subarray(2)]),
      message: MESSAGE,
      signature: HONEST_SIGNATURE,
      valid: false,
      holds: "cofactorless",
      wraps: HONEST.A,
    },
    {
      name: "a key with a trailing byte",
      key: Uint8Array.from([...spki(HONEST.A), 0]),
      message: MESSAGE,
      signature: HONEST_SIGNATURE,
      valid: false,
      holds: "cofactorless",
      wraps: HONEST.A,
    },
    // The BIT STRING's first byte counts the unused bits at its end, and a 32-byte key has none. A library that reads
    // the bit string leniently still takes the 32 bytes after it as the key; this is the one 44-byte key that is not
    // exactly the Ed25519 SPKI, so it separates comparing the prefix from asking a parser whether the bytes are a key.
    {
      name: "a key whose bit string claims an unused bit",
      key: Uint8Array.from([...SPKI_PREFIX.subarray(0, 11), 0x01, ...HONEST.A]),
      message: MESSAGE,
      signature: HONEST_SIGNATURE,
      valid: false,
      holds: "cofactorless",
      wraps: HONEST.A,
    },
    // Cases 17 and 18 set the sign bit on A only. This is the identity's second encoding as R, which a rule 4 built
    // from a list of the eight canonical encodings, rather than from y, would let through.
    honest("R the identity with the sign bit set", MESSAGE, signedWithR(withSignBit(identity)), false, "cofactorless"),
  ];
}

/**
 * Every answer is the generator's own verifyStrict, and every case meant to show one check is refused by that check
 * alone: `holds` says which equation the case satisfies, so a case refused only by rules 1 to 4 does not pass for some
 * other reason, and the cofactored cases pass the equation the rule forbids but not the one it requires. `wraps` marks
 * a key refused by rule 1 alone: written as the Ed25519 SPKI, the key it carries passes rules 2 to 4.
 * `reachesTheLibrary` marks a refused case that rules 1 to 4 pass, and `pinsReducedK` the case whose answer turns on
 * reducing k mod L. An R or A written with y at or above p, or with the sign bit set on x = 0, is also refused by rule
 * 5's own decoding, as rules 3 and 4 refuse it; verifyStrict never reaches that decoding for such a case, so it is
 * checked here.
 */
function checked(cases: Built[]): Built[] {
  for (const c of cases) {
    if (verifyStrict(c.key, c.message, c.signature) !== c.valid) throw new Error(`${c.name}: verifyStrict disagrees with valid`);
    // x = 0 exactly where y² = 1, so whether x is 0 is read from y here, not from the decoding under test.
    for (const point of [c.signature.subarray(0, 32), c.wraps ?? c.key.subarray(12)]) {
      if (point.length !== 32) continue;
      const y = yOf(point);
      const nonCanonical = y >= p || (point[31] >> 7 === 1 && mod(y * y) === 1n);
      if (nonCanonical && decode(point) !== null) throw new Error(`${c.name}: rule 5's decoding takes a non-canonical encoding`);
    }
    if (c.wraps !== undefined && !encodingsHold(spki(c.wraps), c.signature)) throw new Error(`${c.name}: refused by more than rule 1`);
    if (c.reachesTheLibrary && !encodingsHold(c.key, c.signature)) throw new Error(`${c.name}: refused by rules 1 to 4`);
    if (c.pinsReducedK) {
      const digest = littleEndian(sha512(c.signature.subarray(0, 32), c.key.subarray(12), c.message));
      if (mod(digest, L) % 8n !== 0n || digest % 8n === 0n) throw new Error(`${c.name}: does not separate reduced from unreduced k`);
    }
    if (c.holds === undefined) continue;
    const A = c.wraps ?? c.key.subarray(12);
    if (!equationHolds(A, c.signature, c.message, c.holds, true)) throw new Error(`${c.name}: the ${c.holds} equation does not hold`);
    if (c.holds === "cofactored" && equationHolds(A, c.signature, c.message, "cofactorless", true)) {
      throw new Error(`${c.name}: the cofactorless equation holds`);
    }
  }
  return cases;
}

const ABOUT =
  "Paztport's Ed25519 vectors: the signature rule (spec wire.md, Signatures) where Ed25519 libraries disagree. " +
  "Each case gives publicKey, the base64url of the bytes handed to the verifier as an X.509 SPKI (some are not an Ed25519 SPKI), " +
  "message and signature, base64url of the bytes; valid is the rule's answer. " +
  "A replay hands the three to the SDK's verify and expects valid; a key the platform refuses to decode counts as not valid. " +
  "smallOrderY lists the y of every point of small order, each as its 32 little-endian bytes in hex, ascending as numbers: " +
  "the five values rule 4 refuses, tested on the y of R and A with the sign bit ignored. " +
  "In the case names, y8 is smallOrderY's fourth value and p - y8 its third. " +
  "The cases were crafted, and every answer worked out, by RFC 8032 arithmetic written for the generator, which imports no SDK code. " +
  "Cases may be added; a recorded answer changes only with a protocol change.";

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function buildVectorsEd25519(): Record<string, unknown> {
  return {
    about: ABOUT,
    smallOrderY: SMALL_ORDER_Y.map((y) => Buffer.from(bytes32(y)).toString("hex")),
    cases: checked(buildCases()).map((c) => ({
      name: c.name,
      publicKey: b64url(c.key),
      message: b64url(c.message),
      signature: b64url(c.signature),
      valid: c.valid,
    })),
  };
}

export function vectorsEd25519Text(): string {
  return JSON.stringify(buildVectorsEd25519(), null, 2) + "\n";
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes("--write")) {
  writeFileSync(ED25519_JSON, vectorsEd25519Text());
}
