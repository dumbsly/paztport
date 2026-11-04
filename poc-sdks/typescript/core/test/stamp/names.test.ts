// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { stampLocalStep } from "../../src/influence/local-step.ts";
import { mintOrigin } from "../../src/stamp/origin.ts";
import { requireStampableNames } from "../../src/stamp/names.ts";
import { signStamp } from "../../src/stamp/stamp.ts";

const { privateKey } = generateKeyPair();
const BAD = ["", ".", "..", "a/b", "a\\b", "a|b", "a\ud800b"];
const origin = (svc: string, rcv: string) => () => mintOrigin({ svc, rid: "r", ts: 1, bind: "b", sess: "s", inst: "i", rcv }, privateKey);
const localStep = (svc: string, toolName = "read") => () =>
  stampLocalStep(
    {
      svc, inst: "i", rid: "r", ts: 1, prev: "", influence: [], toolName, toolCallId: "c", input: {},
      resolved: { paths: [], programs: [], parse: "ok", readOnly: true }, verdict: "OK", listed: true, rulesHash: null,
    },
    privateKey,
  );

describe("stamping names", () => {
  for (const bad of BAD) {
    const shown = JSON.stringify(bad);
    it(`mintOrigin refuses svc ${shown}`, () => expect(origin(bad, "pi")).toThrow(/^svc must be a route node/));
    it(`mintOrigin refuses rcv ${shown}`, () => expect(origin("session", bad)).toThrow(/^rcv must be a route node/));
    it(`stampLocalStep refuses svc ${shown}`, () => expect(localStep(bad)).toThrow(/^svc must be a route node/));
  }
  it("stampLocalStep leaves the tool part of its receiver alone: an unlisted tool's refusal is still signed", () => {
    expect(localStep("pi", "ext/bash")).not.toThrow();
  });
  it("the message does not quote the value", () => {
    expect(() => requireStampableNames("a/secret", "pi")).toThrow(expect.objectContaining({ message: expect.not.stringContaining("secret") }));
  });
  it("accepts ordinary names, including a surrogate pair", () => {
    expect(() => requireStampableNames("session", "pi😀")).not.toThrow();
  });
  it("signStamp stays the low-level builder and signs an empty rcv", () => {
    expect(() => signStamp({ svc: "s", inst: "i", rid: "r", ts: 1, sess: "", rcv: "", bind: "b", infl: "", prev: "" }, privateKey)).not.toThrow();
  });
});
