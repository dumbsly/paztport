// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned bytes for cross-implementation conformance (any v2 implementation must reproduce
// these). Change only with a protocol change.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  bindPrompt, bindResponse, bindResult, commitInfluence, deriveSessionId, encode, signingBytesV2,
} from "../src/index.ts";

const v = JSON.parse(readFileSync(new URL("../../../spec/vectors/v2.json", import.meta.url), "utf8"));

/** n consecutive bytes starting at `start`, base64url. */
const seq = (start: number, n: number) => encode(Uint8Array.from({ length: n }, (_, i) => start + i));

const fixed = v.fixedInputs as Record<string, { start: number; length: number; encoded: string }>;
const input = (name: string) => seq(fixed[name]!.start, fixed[name]!.length);
const CLIENT_ROOT_SIG = input("clientRootSig"); // 0x01..0x40
const SERVER_ROOT_SIG = input("serverRootSig"); // 0x41..0x80
const CLIENT_NONCE = input("clientNonce"); // 0xa0..0xaf
const SERVER_NONCE = input("serverNonce"); // 0xb0..0xbf
const CLIENT_KEYS = v.deriveSessionId.keys;

describe("v2 known-answer vectors", () => {
  it("fixed inputs encode as expected", () => {
    expect(CLIENT_ROOT_SIG).toBe(fixed.clientRootSig!.encoded);
    expect(SERVER_ROOT_SIG).toBe(fixed.serverRootSig!.encoded);
    expect(CLIENT_NONCE).toBe(fixed.clientNonce!.encoded);
    expect(SERVER_NONCE).toBe(fixed.serverNonce!.encoded);
  });

  it.each((v.deriveSessionId.cases as any[]).map((c): [string, any] => [c.name, c]))("deriveSessionId: %s", (_name, c) => {
    const clientSig = c.clientRootSig === null ? null : input(c.clientRootSig);
    const serverSig = c.serverRootSig === null ? null : input(c.serverRootSig);
    expect(deriveSessionId(clientSig, serverSig, CLIENT_NONCE, SERVER_NONCE, CLIENT_KEYS)).toBe(c.expected);
  });

  it("bindResponse", () => {
    expect(bindResponse(v.bindResponse.resultHash, v.bindResponse.callId, v.bindResponse.labels)).toBe(v.bindResponse.expected);
  });

  it("bindPrompt", () => {
    expect(bindPrompt(v.bindPrompt.prompt)).toBe(v.bindPrompt.expected);
  });

  it("bindResult", () => {
    expect(bindResult(v.bindResult.result)).toBe(v.bindResult.expected);
  });

  it("commitInfluence", () => {
    expect(commitInfluence(v.commitInfluence.entries)).toBe(v.commitInfluence.expected);
  });

  it("signingBytesV2", () => {
    expect(Buffer.from(signingBytesV2(v.signingBytesV2.stamp)).toString("hex")).toBe(v.signingBytesV2.hex);
  });
});
