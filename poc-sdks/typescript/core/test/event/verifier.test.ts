// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import { writeWire } from "../../src/encoding/jcs.ts";
import { generateKeyPair, sign, utf8 } from "../../src/crypto/crypto.ts";
import { eventSigningBytes, signEvent, type EventEnvelope } from "../../src/event/envelope.ts";
import { createEventVerifier, type EventOutcome } from "../../src/event/verifier.ts";

const NOW = 1_000_000;
const payment = generateKeyPair();
const search = generateKeyPair();

/** An event's JCS text, with `ts` written as given. */
function eventJson(ts: number | string, eventId: string): string {
  return `{"audit":false,"eventId":"${eventId}","reason":"PATH_NOT_ALLOWED","rid":"r","suspectInst":"s1","suspectSvc":"search","ts":${ts}}`;
}

/** The envelope's JCS text, the body a sender posts. */
function wire(env: EventEnvelope): string {
  return new TextDecoder().decode(writeWire(env));
}

function envelope(signer: string, key: { privateKey: string }, json: string): string {
  return wire(signEvent(signer, json, key.privateKey));
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
    for (const body of ["not json", "{}", "null", "", '{"payload":"!!","sig":"!!","signer":"payment"}']) {
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
    const body = wire({ signer: "payment", payload: forged.payload, sig: good.sig });
    expect(refusalOf(setup().auth.accept(body))).toBe("BAD_SIGNATURE");
  });

  it("refusesASignatureWithoutTheDomainPrefix", () => {
    const payload = encode(utf8(eventJson(NOW, "a")));
    const sig = encode(sign(payment.privateKey, utf8(payload)));
    expect(refusalOf(setup().auth.accept(wire({ signer: "payment", payload, sig })))).toBe("BAD_SIGNATURE");
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

  it("aNegativeTsIsMalformed", () => {
    const { auth } = setup();
    for (const ts of ["-1", "-9007199254740991", "-0"]) {
      expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(ts, "a")))), ts).toBe("MALFORMED_EVENT");
    }
  });

  it("aTsWrittenWithAFractionIsMalformed", () => {
    const { auth } = setup();
    // A `ts` is a protocol integer by its text: a fraction or an exponent is malformed whatever its value.
    for (const ts of [`${NOW}.0`, `${NOW}.5`, "9007199254740991.4", "1E6", "1000000e0", "0.1e7", "1e999999999", "0e999999999"]) {
      expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(ts, "a")))), ts).toBe("MALFORMED_EVENT");
    }
  });

  it("aTimestampWhoseDifferenceIsHugeIsOutsideTheWindow", () => {
    const max = Number.MAX_SAFE_INTEGER;
    const { auth, clock } = setup();
    clock.now = -max;
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(max, "b"))))).toBe("OUTSIDE_WINDOW");
    clock.now = max;
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(0, "c"))))).toBe("OUTSIDE_WINDOW");
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
    const noId = `{"audit":false,"reason":"X","rid":"r","suspectInst":"","suspectSvc":"","ts":${NOW}}`;
    expect(refusalOf(auth.accept(envelope("payment", payment, noId)))).toBe("NO_EVENT_ID");
    expect(refusalOf(auth.accept(envelope("payment", payment, noId.replace('"audit":false,', '"audit":false,"eventId":null,'))))).toBe("NO_EVENT_ID");
    expect(refusalOf(auth.accept(envelope("payment", payment, eventJson(NOW, ""))))).toBe("NO_EVENT_ID");
    expect(auth.accept(envelope("payment", payment, eventJson(NOW, " ")))).toHaveProperty("event");
  });

  it("aBodyWithALoneSurrogateIsMalformedAndDoesNotThrow", () => {
    const { auth } = setup();
    // Escaped, then raw: either way the body has no UTF-8 form, so it is no envelope's bytes.
    for (const body of ['{"payload":"AA\\ud800","sig":"AAAA","signer":"payment"}', '{"payload":"AA\ud800","sig":"AAAA","signer":"payment"}']) {
      expect(() => auth.accept(body)).not.toThrow();
      expect(auth.accept(body)).toEqual({ refusal: "MALFORMED_ENVELOPE" });
    }
  });

  it("anEnvelopePastTheWireLimitIsMalformed", () => {
    const body = `{"payload":"${"A".repeat(262144)}","sig":"AAAA","signer":"payment"}`;
    expect(refusalOf(setup().auth.accept(body))).toBe("MALFORMED_ENVELOPE");
  });

  it("refusalDoesNotConsumeTheEventId", () => {
    const { auth } = setup();
    const good: EventEnvelope = signEvent("payment", eventJson(NOW, "a"), payment.privateKey);
    expect(refusalOf(auth.accept(wire({ ...good, sig: "AAAA" })))).toBe("BAD_SIGNATURE");
    expect(auth.accept(wire(good))).toHaveProperty("event");
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
    expect(setup().auth.accept('{"payload":"e30","sig":"AAAA","signer":"x\\ny"}')).toEqual({ refusal: "SIGNER_NOT_ALLOWED" });
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
    const event = `{"__proto__":{},"audit":false,"eventId":"a","reason":"X","rid":"","suspectInst":"","suspectSvc":"","ts":${NOW}}`;
    expect(refusalOf(auth.accept(envelope("payment", payment, event)))).toBe("MALFORMED_EVENT");
  });

  it("refusesAnEnvelopeWithAnotherMemberOrTrailingText", () => {
    const { auth } = setup();
    const good = envelope("payment", payment, eventJson(NOW, "a"));
    expect(refusalOf(auth.accept(good.replace("{", '{"kid":"k",')))).toBe("MALFORMED_ENVELOPE");
    expect(refusalOf(auth.accept(good + " x"))).toBe("MALFORMED_ENVELOPE");
    expect(refusalOf(auth.accept("﻿" + good))).toBe("MALFORMED_ENVELOPE");
  });

  it("anEnvelopeInWireMemberOrderIsMalformed", () => {
    const env = signEvent("payment", eventJson(NOW, "a"), payment.privateKey);
    const body = `{"signer":"payment","payload":"${env.payload}","sig":"${env.sig}"}`;
    expect(refusalOf(setup().auth.accept(body))).toBe("MALFORMED_ENVELOPE");
  });

  it("aPayloadInWireMemberOrderIsMalformedEvent", () => {
    const json = `{"reason":"PATH_NOT_ALLOWED","suspectSvc":"search","suspectInst":"s1","rid":"r","audit":false,"ts":${NOW},"eventId":"a"}`;
    expect(refusalOf(setup().auth.accept(envelope("payment", payment, json)))).toBe("MALFORMED_EVENT");
  });

  it("whitespaceAroundTheBodyIsMalformed", () => {
    const { auth } = setup();
    const good = envelope("payment", payment, eventJson(NOW, "a"));
    expect(refusalOf(auth.accept(" \n\t" + good + "\r\n "))).toBe("MALFORMED_ENVELOPE");
    expect(refusalOf(auth.accept(good + "\n"))).toBe("MALFORMED_ENVELOPE");
  });

  it("whitespaceAroundThePayloadIsMalformedEvent", () => {
    expect(refusalOf(setup().auth.accept(envelope("payment", payment, " \n" + eventJson(NOW, "a") + "\n")))).toBe("MALFORMED_EVENT");
  });

  it("readsThePayloadAsStrictUtf8WithoutAByteOrderMark", () => {
    const { auth } = setup();
    const sign2 = (bytes: Uint8Array) => {
      const payload = encode(bytes);
      return wire({ signer: "payment", payload, sig: encode(sign(payment.privateKey, eventSigningBytes(payload))) });
    };
    const json = utf8(eventJson(NOW, "a"));
    expect(refusalOf(auth.accept(sign2(Uint8Array.from([0xef, 0xbb, 0xbf, ...json]))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(sign2(Uint8Array.from([...json.slice(0, 20), 0xff, ...json.slice(20)]))))).toBe("MALFORMED_EVENT");
    expect(refusalOf(auth.accept(sign2(Uint8Array.from([...json.slice(0, 20), 0xed, 0xa0, 0x80, ...json.slice(20)]))))).toBe("MALFORMED_EVENT");
  });
});
