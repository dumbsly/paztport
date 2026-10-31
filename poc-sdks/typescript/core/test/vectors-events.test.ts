// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Replays spec/vectors/events.json: the signed bytes of each envelope case, and every verify case against a fresh responder.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { encode } from "../src/encoding/b64url.ts";
import { utf8 } from "../src/crypto/crypto.ts";
import { eventSigningBytes, signEvent } from "../src/event/envelope.ts";
import { isAttributable } from "../src/event/attributable.ts";
import { createEventVerifier, type EventOutcome, type EventRefusal } from "../src/event/verifier.ts";

type VerifyCase = {
  name: string;
  earlier: { body: string; now: number }[];
  body: string;
  now: number;
  uses: number;
  expected: { refusal: string | null; event: unknown };
};
const v = JSON.parse(readFileSync(new URL("../../../spec/vectors/events.json", import.meta.url), "utf8"));

function run(c: VerifyCase): EventOutcome {
  const clock = { now: 0 };
  const verifier = createEventVerifier({ keyring: v.responder.keyring, allowedSigners: v.responder.allowedSigners, now: () => clock.now });
  for (const e of c.earlier) {
    clock.now = e.now;
    verifier.accept(e.body);
  }
  clock.now = c.now;
  let got: EventOutcome | undefined;
  for (let i = 0; i < c.uses; i++) got = verifier.accept(c.body);
  return got!;
}

describe("event vectors", () => {
  it.each(v.envelope as any[])("envelope: $name", (c) => {
    expect(JSON.stringify(c.event)).toBe(c.eventJson);
    const env = signEvent(c.signer, c.eventJson, v.keys[c.signer].priv);
    expect(env.payload).toBe(c.payload);
    expect(encode(eventSigningBytes(env.payload))).toBe(c.signingBytes);
    expect(env.sig).toBe(c.sig);
    expect(encode(utf8("paztport-event\n" + env.payload))).toBe(c.signingBytes);
  });

  it.each(v.verify as VerifyCase[])("verify: $name", (c) => {
    const got = run(c);
    if ("event" in got) {
      expect(c.expected.refusal).toBeNull();
      expect(got.event).toEqual(c.expected.event);
    } else {
      expect(got.refusal).toBe(c.expected.refusal);
      expect(c.expected.event).toBeNull();
    }
  });

  it.each(v.attributable as { name: string; event: any; expected: boolean }[])("attributable: $name", (c) => {
    expect(isAttributable(c.event)).toBe(c.expected);
  });

  it("every refusal and an acceptance each have a case", () => {
    const all: EventRefusal[] = [
      "MALFORMED_ENVELOPE", "SIGNER_NOT_ALLOWED", "UNKNOWN_SIGNER", "BAD_SIGNATURE", "MALFORMED_EVENT", "NO_EVENT_ID", "OUTSIDE_WINDOW", "REPEATED_EVENT_ID",
    ];
    const seen = new Set((v.verify as VerifyCase[]).map((c) => c.expected.refusal ?? "accepted"));
    expect(seen.has("accepted")).toBe(true);
    for (const r of all) expect(seen.has(r), r).toBe(true);
  });
});
