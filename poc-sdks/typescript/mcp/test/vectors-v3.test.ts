// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned v3 vectors for cross-implementation conformance: every case is replayed from the committed JSON
// alone. Cases may be added; a recorded answer changes only with a protocol change.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  NonceCache, canonicalize, commitInfluence, decode, encode, isAttestedSession, sessionStatus, isCurrent, isReplyCert, issueReplyCert, keyringSigningBytes, normalizeInfluence,
  publicWriteRefused, replyCertSigningBytes, rootSigningBytes, sign, signKeyring, signKeyringOldForm, signRoot, signRootOldForm, signSessionReply, signingBytesV3, utf8, verifyChainOffline,
  verifyChainV3, verifyKeyring, verifyReplyCert, verifyRoot,
} from "@paztport/core";
import type { OfflineConfig, OfflineInput, SessionReply, V3Config, V3Input } from "@paztport/core";
import { classifySessionReply } from "../src/index.ts";
import { buildVectorsV3, vectorsV3Text } from "./vectors-v3-export.ts";

type Sections = "signingBytesV3" | "signatures" | "influence" | "rule" | "keyring" | "root" | "verify" | "offline" | "replyCert" | "sessionReply" | "sessionStatus";
const committedText = readFileSync(new URL("../../../spec/vectors/v3.json", import.meta.url), "utf8");
const committed: Record<Sections, any[]> & { keys: Record<string, { pub: string; priv: string }>; policies: any } = JSON.parse(committedText);

/** The config fields both verifiers share, from a case's names: keys from `keys`, the root and proof from `policies`. */
function shared(v: any, c: any) {
  const policy = v.policies[c.policy];
  const keyring = Object.fromEntries(Object.entries(c.keyring as Record<string, string>).map(([svc, name]) => [svc, v.keys[name].pub as string]));
  const cfg = { keyring, root: decode(policy.root), rootId: policy.rootId as string, allowedOrigins: c.allowedOrigins, sess: c.sess, nonceKey: c.nonceKey };
  const input = {
    stamps: c.chain,
    expectedBind: c.expectedBind,
    influence: c.influence,
    proof: c.proofRoute === null ? null : policy.proofs[c.proofRoute],
    receiver: c.receiver,
    receiverInRoute: c.receiverInRoute,
  };
  return { cfg, input };
}

/** Runs a live case `uses` times against one nonce cache; the last result. */
function replayLive(v: any, c: any) {
  const { cfg, input } = shared(v, c);
  const live: V3Config = { ...cfg, nonces: new NonceCache(c.nonceTtlMs), now: c.now, callMaxAgeMs: c.callMaxAgeMs, runMaxAgeMs: c.runMaxAgeMs, policyNotAfter: c.policyNotAfter };
  const full: V3Input = c.peer === null ? input : { ...input, peer: c.peer };
  let result = verifyChainV3(full, live);
  for (let i = 1; i < c.uses; i++) result = verifyChainV3(full, live);
  return { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst };
}

/** Runs an offline case against the record set's spent nonce keys, `seen`. */
function replayOffline(v: any, c: any) {
  const { cfg, input } = shared(v, c);
  const recordedTs = c.recordedTs.run === undefined ? { last: c.recordedTs.last } : { last: c.recordedTs.last, run: new Set<number>(c.recordedTs.run) };
  const offline: OfflineConfig = { ...cfg, seen: new Set<string>(c.seen), callMaxAgeMs: c.callMaxAgeMs, runMaxAgeMs: c.runMaxAgeMs };
  const full: OfflineInput = { ...input, rid: c.rid, recordedTs, prompt: c.prompt };
  const result = verifyChainOffline(full, offline);
  return { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst, legacy: result.legacy };
}

describe("v3 known-answer vectors", () => {
  it("the committed file is what the exporter builds", () => expect(buildVectorsV3()).toEqual(committed));
  it("the committed file is byte for byte what the exporter writes", () => expect(committedText).toBe(vectorsV3Text()));
  it.each(committed.signingBytesV3.map((c: any): [string, any] => [c.hex, c]))("signing bytes %s", (_h, c: any) => expect(Buffer.from(signingBytesV3(c.stamp)).toString("hex")).toBe(c.hex));
  it.each(committed.signingBytesV3.map((c: any): [string, any] => [c.hex, c]))("signing bytes %s are the fields joined by |", (_h, c: any) => {
    const s = c.stamp;
    expect(Buffer.from(utf8([3, s.svc, s.inst, s.rid, s.ts, s.sess, s.rcv, s.bind, s.infl, s.prev].join("|"))).toString("hex")).toBe(c.hex);
  });
  it.each(committed.signatures.map((c: any, i: number): [number, any] => [i, c]))("signature %i", (_i, c: any) => expect(encode(sign(committed.keys[c.key].priv, signingBytesV3({ v: 3, ...c.fields })))).toBe(c.sig));
  it.each(committed.influence.map((c: any): [string, any] => [c.name, c]))("influence %s", (_n, c: any) => {
    expect(normalizeInfluence(c.entries)).toEqual(c.normalized);
    expect(commitInfluence(c.entries)).toBe(c.commitment);
  });
  it.each(committed.rule.map((c: any): [string, any] => [c.name, c]))("rule %s", (_n, c: any) => expect(publicWriteRefused(c.influence, c.destinationOwner ?? undefined)).toBe(c.refused));
  it.each(committed.keyring.map((c: any): [string, any] => [c.name, c]))("keyring %s", (_n, k: any) => {
    expect(verifyKeyring(k.signed, committed.keys[k.policyKey].pub)).toBe(k.verifies);
    for (const { at, current } of k.current ?? []) expect(isCurrent(k.signed, at), String(at)).toBe(current);
    // Every keyring that verifies is reproduced byte for byte by signing it in its own form.
    const notAfter = Object.hasOwn(k.signed, "notAfter") ? k.signed.notAfter : undefined;
    const priv = committed.keys[k.policyKey].priv;
    if (k.verifies) expect((notAfter === undefined ? signKeyringOldForm(k.signed.services, k.signed.policy, priv) : signKeyring(k.signed.services, k.signed.policy, priv, notAfter)).sig).toBe(k.sig);
  });
  it("root section", () => expect(committed.root.length).toBeGreaterThan(0));
  it.each(committed.root.map((c: any): [string, any] => [c.name, c]))("root %s", (_n, r: any) => {
    const { rootId, root, sig } = r.signed;
    const windowed = Object.hasOwn(r.signed, "notAfter");
    const notAfter = windowed ? r.signed.notAfter : undefined;
    expect(verifyRoot(r.signed, committed.keys[r.policyKey].pub)).toBe(r.verifies);
    expect(root).toBe(committed.policies[r.policy].root);
    expect(rootId).toBe(committed.policies[r.policy].rootId);
    for (const { at, current } of r.current ?? []) expect(isCurrent(r.signed, at), String(at)).toBe(current);
    if (r.signingBytes === null) {
      expect(windowed).toBe(true);
      expect(() => rootSigningBytes(rootId, root, notAfter)).toThrow(TypeError);
    } else {
      expect(encode(rootSigningBytes(rootId, root, notAfter))).toBe(r.signingBytes);
      const literal = windowed ? "paztport-root\n" + canonicalize({ notAfter, root, rootId }) : `${rootId}|${root}`;
      expect(encode(utf8(literal))).toBe(r.signingBytes);
    }
    // Every root that verifies is reproduced byte for byte by signing it in its own form.
    const priv = committed.keys[r.policyKey].priv;
    if (r.verifies) expect((notAfter === undefined ? signRootOldForm(decode(root), rootId, priv) : signRoot(decode(root), rootId, priv, notAfter)).sig).toBe(sig);
  });

  // The cases that tie the readers' reading of a notAfter together: 2^53 is refused, and a value written with a
  // fraction is read as the integer it equals, the one its signature is over.
  it.each(["keyring", "root"] as const)("%s notAfter is judged by value", (section) => {
    const byName = (name: string) => committed[section].find((c: any) => c.name === name);
    const verify = (c: any) => (section === "keyring" ? verifyKeyring(c.signed, committed.keys[c.policyKey].pub) : verifyRoot(c.signed, committed.keys[c.policyKey].pub));
    const tooLarge = byName("notAfter 2^53");
    expect(tooLarge.signed.notAfter).toBe(2 ** 53);
    expect(tooLarge.signingBytes).toBeNull();
    expect(verify(tooLarge)).toBe(false);
    const written = byName("notAfter written 1798761600000.0");
    expect(written.signed.notAfter).toBe(1_798_761_600_000);
    expect(verify(written)).toBe(true);
    expect(written.signingBytes).toBe(byName("new form").signingBytes);
    expect(written.sig ?? written.signed.sig).toBe(byName("new form").signed.sig);
    // the file spells it with a fraction, once per section, so the text reaches each reader as written
    const section0 = committedText.indexOf(`\n  "${section}": [`);
    const at = committedText.indexOf('"name": "notAfter written 1798761600000.0"', section0);
    expect(committedText.slice(at, committedText.indexOf('"verifies"', at))).toContain('"notAfter": 1798761600000.0\n');
  });
  it.each(committed.verify.map((c: any): [string, any] => [c.name, c]))("verify %s", (_n, c: any) => expect(replayLive(committed, c)).toEqual(c.expected));
  it.each(committed.offline.map((c: any): [string, any] => [c.name, c]))("offline %s", (_n, c: any) => expect(replayOffline(committed, c)).toEqual(c.expected));

  it.each(committed.replyCert.map((c: any): [string, any] => [c.name, c]))("reply certificate %s", (_n, c: any) => {
    const { policy, svc, key, notAfter, sig } = c.cert;
    expect(isReplyCert(c.cert)).toBe(true);
    expect(encode(replyCertSigningBytes(policy, svc, key, notAfter))).toBe(c.signingBytes);
    expect(encode(utf8("paztport-reply-cert\n" + canonicalize({ key, notAfter, policy, svc })))).toBe(c.signingBytes);
    expect(verifyReplyCert(c.cert, committed.keys[c.pin].pub)).toBe(c.verifies);
    // Every certificate that verifies is reproduced byte for byte by issuing it.
    if (c.verifies) expect(issueReplyCert(policy, svc, key, notAfter, committed.keys[c.signer].priv).sig).toBe(sig);
  });

  it("session reply section", () => expect(committed.sessionReply.length).toBeGreaterThan(0));

  // The cases the live check refuses only for the server's root or keyring being in the old form: offline, a recorded
  // handshake is accepted in the old forms. A new-form window is judged offline too, at the record's time (`now`), so
  // the expired cases are refused there as well.
  const OFFLINE_ACCEPTS = new Set(["server root old form", "server root old form, policy-key form", "server keyring old form"]);
  it("the cases offline accepts are in the file", () => {
    for (const name of OFFLINE_ACCEPTS) expect(committed.sessionReply.find((c: any) => c.name === name)?.expected, name).toBe("BAD_SIGNATURE");
  });
  it.each(committed.sessionReply.map((c: any): [string, any] => [c.name, c]))("session reply %s", (_n, c: any) => {
    const pin = committed.keys[c.pin].pub;
    const outcome = classifySessionReply(c.reply, c.request, pin, c.serverEntry, c.now);
    expect(outcome.status === "attested" ? "ATTESTED" : outcome.reason).toBe(c.expected);
    // Offline, judged at the same time, the handshake is attested when the live check says so, and for the old forms.
    expect(isAttestedSession(c.request, c.reply, pin, c.serverEntry, c.now)).toBe(c.expected === "ATTESTED" || OFFLINE_ACCEPTS.has(c.name));
  });

  it("session status section", () => expect(committed.sessionStatus.length).toBeGreaterThan(0));

  it.each(committed.sessionStatus.map((c: any): [string, any] => [c.name, c]))("session status %s", (_n, c: any) => {
    const ring = c.serverKeyring;
    const ringNotAfter = Object.hasOwn(ring, "notAfter") ? ring.notAfter : undefined;
    const pinned = c.pinned.map((n: string) => committed.keys[n].pub);
    expect(sessionStatus(c.request, c.serverRoot, ringNotAfter, committed.keys[c.serverPolicyKey].pub, pinned, c.now)).toBe(c.expected);
    // the server's own keyring is the one it signed, in its own form
    expect(verifyKeyring(ring, committed.keys[c.serverPolicyKey].pub)).toBe(true);
  });

  // A configured entry named like an Object.prototype member must not find a key in a keyring that lacks it. Here
  // the keyring inherits the entry, holding the certificate's key, so only the own-member check stops the reply. It
  // is a proxy rather than Object.create's, since JCS refuses an object whose prototype is not Object.prototype: to
  // JCS and Object.keys it is the signed keyring, while a lookup finds the entry as an inherited member would.
  it.each(["constructor", "__proto__", "toString"])("protoEntryHasNoKey %s", (entry) => {
    const good = committed.sessionReply.find((c: any) => c.name === "new form attested");
    const keys = committed.keys;
    const cert = issueReplyCert(keys["server-policy"].pub, entry, keys["mcp-entry"].pub, good.reply.serverReplyCert.notAfter, keys["server-policy"].priv);
    expect(verifyReplyCert(cert, keys["server-policy"].pub)).toBe(true);
    const services: Record<string, string> = { ...good.reply.serverKeyring };
    const inherits = new Proxy(services, {
      get: (t, p, r) => (p === entry && !Object.hasOwn(t, p) ? cert.key : Reflect.get(t, p, r)),
    });
    expect(Object.hasOwn(inherits, entry)).toBe(false);
    expect(inherits[entry]).toBe(cert.key);
    expect(Object.getPrototypeOf(inherits)).toBe(Object.prototype);
    const ring = { policy: keys["server-policy"].pub, services: inherits, sig: good.reply.serverKeyringSig, notAfter: good.reply.serverKeyringNotAfter };
    expect(verifyKeyring(ring, keys["server-policy"].pub)).toBe(true);
    const { sig: _sig, ...body } = good.reply;
    const reply = signSessionReply({ ...body, serverKeyring: inherits, serverReplyCert: cert } as Omit<SessionReply, "sig">, keys["mcp-entry"].priv);
    expect(classifySessionReply(reply, good.request, keys["server-policy"].pub, entry, good.now)).toEqual({
      status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true,
    });
    expect(isAttestedSession(good.request, reply, keys["server-policy"].pub, entry, good.now)).toBe(false);
  });

  it("keyring signing bytes and named services match the signed keyring", () => {
    for (const k of committed.keyring) {
      const { policy, services } = k.signed;
      const windowed = Object.hasOwn(k.signed, "notAfter");
      const notAfter = windowed ? k.signed.notAfter : undefined;
      if (k.signingBytes === null) {
        expect(windowed, k.name).toBe(true);
        expect(() => keyringSigningBytes(policy, services, notAfter), k.name).toThrow(TypeError);
      } else {
        expect(encode(keyringSigningBytes(policy, services, notAfter)), k.name).toBe(k.signingBytes);
        const body = windowed ? canonicalize({ notAfter, policy, services }) : canonicalize({ policy, services });
        expect(encode(utf8("paztport-keyring\n" + body)), k.name).toBe(k.signingBytes);
      }
      expect(k.signed.sig).toBe(k.sig);
      const named = Object.fromEntries(Object.entries(k.services as Record<string, string>).map(([svc, name]) => [svc, committed.keys[name].pub]));
      expect(k.signed.services).toEqual(named);
      expect(k.signed.policy).toBe(committed.keys[k.policyKey].pub);
    }
  });
});
