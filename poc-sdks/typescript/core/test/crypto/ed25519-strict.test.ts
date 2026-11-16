// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// strictEncodings on its own, at the boundaries of rules 2 to 4. The libraries behind verify refuse most of these
// bytes too, so the vector replay alone cannot show the check makes them. Every row is built from integers written
// here, not from the module's constants, so the test also pins L and p. The Java and Go SDKs carry the same rows.

import { describe, expect, it } from "vitest";
import { strictEncodings } from "../../src/crypto/ed25519-strict.ts";

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const p = 2n ** 255n - 19n;
const Y8 = 55188659117513257062467267217118295137698188065244968500265048394206261417927n;
/** A y that no rule refuses, for the point a row is not about. */
const MID = 2n ** 254n;

function le32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((n >> BigInt(8 * i)) & 0xffn);
  return out;
}

/** A point's encoding: y little-endian, the sign bit in the top bit of the last byte. */
function point(y: bigint, sign: 0 | 1): Uint8Array {
  return le32(y | (BigInt(sign) << 255n));
}

function signature(R: Uint8Array, S: bigint): Uint8Array {
  return Uint8Array.from([...R, ...le32(S)]);
}

type Row = [name: string, a: Uint8Array, signature: Uint8Array, want: boolean];

function rows(): Row[] {
  const fine = point(MID, 0);
  const out: Row[] = [
    ["S = L - 1", fine, signature(fine, L - 1n), true],
    ["S = L", fine, signature(fine, L), false],
    ["S with bit 255 set", fine, signature(fine, 1n | (1n << 255n)), false],
  ];
  for (const sign of [0, 1] as const) {
    out.push([`R with y = p - 2, sign ${sign}`, fine, signature(point(p - 2n, sign), 1n), true]);
    out.push([`A with y = p - 2, sign ${sign}`, point(p - 2n, sign), signature(fine, 1n), true]);
  }
  for (const [label, y] of [["p", p], ["2^255 - 1", 2n ** 255n - 1n]] as const) {
    out.push([`R with y = ${label}`, fine, signature(point(y, 0), 1n), false]);
    out.push([`A with y = ${label}`, point(y, 0), signature(fine, 1n), false]);
  }
  for (const [label, y] of [["0", 0n], ["1", 1n], ["p - 1", p - 1n], ["y8", Y8], ["p - y8", p - Y8]] as const) {
    for (const sign of [0, 1] as const) {
      out.push([`R with y = ${label}, sign ${sign}`, fine, signature(point(y, sign), 1n), false]);
      out.push([`A with y = ${label}, sign ${sign}`, point(y, sign), signature(fine, 1n), false]);
    }
  }
  const sig = signature(fine, 1n);
  out.push(["a key of 31 bytes", fine.subarray(0, 31), sig, false]);
  out.push(["a key of 33 bytes", Uint8Array.from([...fine, 0]), sig, false]);
  out.push(["a signature of 63 bytes", fine, sig.subarray(0, 63), false]);
  out.push(["a signature of 65 bytes", fine, Uint8Array.from([...sig, 0]), false]);
  return out;
}

describe("strictEncodings", () => {
  it("hasEveryRow", () => {
    expect(rows()).toHaveLength(35);
  });

  it.each(rows())("%s", (_name, a, sig, want) => {
    expect(strictEncodings(a, sig)).toBe(want);
  });
});
