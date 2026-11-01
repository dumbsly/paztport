// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, sign, utf8 } from "../../src/crypto/crypto.ts";
import { eventSigningBytes, signEvent, type EventEnvelope } from "../../src/event/envelope.ts";
import { createEventVerifier, type EventOutcome } from "../../src/event/verifier.ts";

const NOW = 1_000_000;
const payment = generateKeyPair();
const search = generateKeyPair();

function eventJson(ts: number | string, eventId: string): string {
  return `{"reason":"PATH_NOT_ALLOWED","suspectSvc":"search","suspectInst":"s1","rid":"r","audit":false,"ts":${ts},"eventId":"${eventId}"}`;
}

function envelope(signer: string, key: { privateKey: string }, json: string): string {
  return JSON.stringify(signEvent(signer, json, key.privateKey));
}

function setup(clock = { now: NOW }, allowedSigners: string[] = ["payment"]) {
  const auth = createEventVerifier({
    keyring: { payment: payment.publicKey, search: search.publicKey },
    allowedSigners,
    now: () => clock.now,
  });
  return { auth, clock };
}

const refusalOf = (o: EventOutcome) => ("refusal" in o ? o.refusal : undefined);

describe("event verifier", () => {
  it("acceptsAFreshCorrectlySignedEvent", () => {
    const { auth } = setup();
    const got = auth.accept(envelope("payment", payment, eventJson(NOW, "a")));
    expect(got).toEqual({ event: { reason: "PATH_NOT_ALLOWED", suspectSvc: "search", suspectInst: "s1", rid: "r", audit: false, ts: NOW, eventId: "a" } });
  });

  it("refusesAnUnsignedPlainEvent", () => {
    expect(refusalOf(setup().auth.accept(eventJson(NOW, "a")))).toBe("MALFORMED_ENVELOPE");
  });

  it("refusesGarbageAndNull", () => {
    const { auth } = setup();
    for (const body of ["not json", "{}", "null", "", '{"signer":"payment","payload":"!!","sig":"!!"}']) {
      expect(auth.accept(body)).not.toHaveProperty("event");
    }
  });

  it("refusesAnUnknownSigner", () => {
    expect(refusalOf(setup().auth.accept(envelope("ghost", payment, eventJson(NOW, "a"))))).toBe("SIGNER_NOT_ALLOWED");
  });

  it("refusesAKnownButDisallowedSigner", () => {
    expect(refusalOf(setup().auth.accept(envelope("search", search, eventJson(NOW, "a"))))).toBe("SIGNER_NOT_ALLOWED");
  });

  it("refusesASignerClaimingAnotherServicesName", () => {
    expect(refusalOf(setup().auth.accept(envelope("payment", search, eventJson(NOW, "a"))))).toBe("BAD_SIGNATURE");
  });

  it("refusesATamperedPayload", () => {
    const good = signEvent("payment", eventJson(NOW, "a"), payment.privateKey);
    const forged = signEvent("payment", eventJson(NOW, "b"), payment.privateKey);
    const body = JSON.stringify({ signer: "payment", payload: forged.payload, sig: good.sig });
    expect(refusalOf(setup().auth.accept(body))).toBe("BAD_SIGNATURE");
  });

  it("refusesASignatureWithoutTheDomainPrefix", () => {
    const payload = encode(utf8(eventJson(NOW, "a")));
    const sig = encode(sign(payment.privateKey, utf8(payload)));
    expect(refusalOf(setup().auth.accept(JSON.stringify({ signer: "payment", payload, sig })))).toBe("BAD_SIGNATURE");
  });

  it("signsTheDomainPrefixedPayloadText", () => {
    expect(new TextDecoder().decode(eventSigningBytes("abc"))).toBe("paztport-event\nabc");
  });

  it("refusesAStaleEventAndAFutureEvent", () => {
    const { auth } = setup();
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(NOW - 30_001, "a"))))).toBe("OUTSIDE_WINDOW");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(NOW + 30_001, "b"))))).toBe("OUTSIDE_WINDOW");
    expect(auth.accept(envelope("payment", payment, eventJson(NOW - 30_000, "c")))).toHaveProperty("event");
    expect(auth.accept(envelope("payment", payment, eventJson(NOW + 30_000, "d")))).toHaveProperty("event");
  });

  it("aTimestampPastTwoToTheFiftyThreeIsMalformed", () => {
    const { auth } = setup();
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson("9007199254740992", "a"))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson("-9223372036854775808", "b"))))).toBe("MALFORMED_EVENT");
  });

  it("aTimestampWrittenWithAFractionThatRoundsToAnIntegerIsMalformed", () => {
    const { auth } = setup();
    // As a double this is 9007199254740991, so only the written text shows it is not an integer.
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson("9007199254740991.4", "a"))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(`${NOW}.00000000000000000001`, "b"))))).toBe("MALFORMED_EVENT");
  });

  it("aTimestampIsReadByValue", () => {
    const { auth } = setup();
    for (const [text, id] of [[`${NOW}.0`, "a"], ["1E6", "b"], ["1000000e0", "c"], ["10000e2", "d"], ["0.1e7", "e"], ["1000000.000e0", "f"]] as const) {
      const got = auth.accept(envelope("payment", payment, eventJson(text, id)));
      expect(got, text).toHaveProperty("event");
      expect((got as { event: { ts: number } }).event.ts).toBe(NOW);
    }
  });

  it("aTimestampWithAHugeExponentIsMalformedWithoutWork", () => {
    const { auth } = setup();
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson("1e999999999", "a"))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson("1e-999999999", "b"))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson("0e999999999", "c"))))).toBe("OUTSIDE_WINDOW");
  });

  it("aTimestampWhoseDifferenceIsHugeIsOutsideTheWindow", () => {
    const max = Number.MAX_SAFE_INTEGER;
    const { auth, clock } = setup();
    clock.now = -max;
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(max, "b"))))).toBe("OUTSIDE_WINDOW");
    clock.now = max;
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(-max, "c"))))).toBe("OUTSIDE_WINDOW");
  });

  it("refusesARepeatedEventId", () => {
    const { auth } = setup();
    const body = envelope("payment", payment, eventJson(NOW, "a"));
    expect(auth.accept(body)).toHaveProperty("event");
    expect(refusalOf(auth.accept(body))).toBe("REPEATED_EVENT_ID");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(NOW + 1, "a"))))).toBe("REPEATED_EVENT_ID");
  });

  it("remembersAnIdForAtLeastTwiceTheWindow", () => {
    const { auth, clock } = setup();
    const body = envelope("payment", payment, eventJson(NOW + 30_000, "a"));
    expect(auth.accept(body)).toHaveProperty("event");
    clock.now = NOW + 60_000;
    expect(refusalOf(auth.accept(body))).toBe("REPEATED_EVENT_ID");
  });

  it("forgetsAnIdOnceItsTimestampIsOutsideTheWindow", () => {
    const { auth, clock } = setup();
    const body = envelope("payment", payment, eventJson(NOW, "a"));
    expect(auth.accept(body)).toHaveProperty("event");
    clock.now = NOW + 30_001;
    expect(refusalOf(auth.accept(body))).toBe("OUTSIDE_WINDOW");
  });

  it("refusesAMissingOrEmptyEventId", () => {
    const { auth } = setup();
    const noId = `{"reason":"X","suspectSvc":"","suspectInst":"","rid":"r","audit":false,"ts":${NOW}}`;
    expect(refusalOf(auth.accept(envelope("payment", payment, noId)))).toBe("NO_EVENT_ID");
    expect(refusalOf(auth.accept(envelope("payment", payment, noId.replace("}", ',"eventId":null}'))))).toBe("NO_EVENT_ID");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(NOW, ""))))).toBe("NO_EVENT_ID");
    expect(auth.accept(envelope("payment", payment, eventJson(NOW, " ")))).toHaveProperty("event");
  });

  it("aPayloadWithALoneSurrogateIsBadSignatureAndDoesNotThrow", () => {
    const { auth } = setup();
    const body = '{"signer":"payment","payload":"AA\\ud800","sig":"AAAA"}';
    expect(() => auth.accept(body)).not.toThrow();
    expect(auth.accept(body)).toEqual({ refusal: "BAD_SIGNATURE", signer: "payment" });
  });

  it("refusalDoesNotConsumeTheEventId", () => {
    const { auth } = setup();
    const good: EventEnvelope = signEvent("payment", eventJson(NOW, "a"), payment.privateKey);
    expect(refusalOf(auth.accept(JSON.stringify({ ...good, sig: "AAAA" })))).toBe("BAD_SIGNATURE");
    expect(auth.accept(JSON.stringify(good))).toHaveProperty("event");
  });

  it("refusalsCarryTheirTypedReason", () => {
    const { auth } = setup();
    expect(refusalOf(auth.accept("not json"))).toBe("MALFORMED_ENVELOPE");
    const body = envelope("payment", payment, eventJson(NOW, "r"));
    auth.accept(body);
    expect(refusalOf(auth.accept(body))).toBe("REPEATED_EVENT_ID");
  });

  it("onlyAnAllowedSignersNameTravelsWithTheRefusal", () => {
    const keyless = createEventVerifier({ keyring: { search: search.publicKey }, allowedSigners: ["payment"], now: () => NOW });
    expect(keyless.accept(envelope("payment", payment, eventJson(NOW, "a")))).toEqual({ refusal: "UNKNOWN_SIGNER", signer: "payment" });
    expect(setup().auth.accept('{"signer":"x\\ny","payload":"e30","sig":"AAAA"}')).toEqual({ refusal: "SIGNER_NOT_ALLOWED" });
    expect(setup().auth.accept(envelope("payment", search, eventJson(NOW, "a")))).toEqual({ refusal: "BAD_SIGNATURE", signer: "payment" });
  });

  it("looksTheSignerUpByOwnNameOnly", () => {
    const { auth } = setup({ now: NOW }, ["toString", "__proto__", "constructor"]);
    for (const name of ["toString", "constructor"]) {
      expect(auth.accept(envelope(name, payment, eventJson(NOW, name)))).toEqual({ refusal: "UNKNOWN_SIGNER", signer: name });
    }
  });

  it("readsTheEventsMembersByOwnNameOnly", () => {
    const { auth } = setup();
    const event = `{"__proto__":{},"reason":"X","suspectSvc":"","suspectInst":"","rid":"","audit":false,"ts":${NOW},"eventId":"a"}`;
    expect(refusalOf(auth.accept(envelope("payment", payment, event)))).toBe("MALFORMED_EVENT");
  });

  it("refusesAnEnvelopeWithAnotherMemberOrTrailingText", () => {
    const { auth } = setup();
    const good = envelope("payment", payment, eventJson(NOW, "a"));
    expect(refusalOf(auth.accept(good.replace("}", ',"kid":"k"}')))).toBe("MALFORMED_ENVELOPE");
    expect(refusalOf(auth.accept(good + " x"))).toBe("MALFORMED_ENVELOPE");
    expect(refusalOf(auth.accept("﻿" + good))).toBe("MALFORMED_ENVELOPE");
    expect(auth.accept(" \n\t" + good + "\r\n ")).toHaveProperty("event");
  });

  it("readsThePayloadAsStrictUtf8WithoutAByteOrderMark", () => {
    const { auth } = setup();
    const sign2 = (bytes: Uint8Array) => {
      const payload = encode(bytes);
      return JSON.stringify({ signer: "payment", payload, sig: encode(sign(payment.privateKey, eventSigningBytes(payload))) });
    };
    const json = utf8(eventJson(NOW, "a"));
    expect(refusalOf(auth.accept(sign2(Uint8Array.from([0xef, 0xbb, 0xbf, ...json]))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(sign2(Uint8Array.from([...json.slice(0, 20), 0xff, ...json.slice(20)]))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(sign2(Uint8Array.from([...json.slice(0, 20), 0xed, 0xa0, 0x80, ...json.slice(20)]))))).toBe("MALFORMED_EVENT");
  });

  it("refusesAnEventWhenTheRuntimeGivesNoSourceTextForANumber", () => {
    const real = JSON.parse;
    // A runtime without source-text access calls the reviver with two arguments only.
    const spy = vi.spyOn(JSON, "parse").mockImplementation((text: string, reviver?: (k: string, v: unknown) => unknown) =>
      reviver === undefined ? real(text) : real(text, (k, v) => reviver(k, v)),
    );
    try {
      const { auth } = setup();
      expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(NOW, "a"))))).toBe("MALFORMED_EVENT");
    } finally {
      spy.mockRestore();
    }
  });
});
