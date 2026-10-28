// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned v3 vectors for cross-implementation conformance: every case is replayed from the committed JSON
// alone. Cases may be added; a recorded answer changes only with a protocol change.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  NonceCache, canonicalize, commitInfluence, decode, encode, isAttestedSession, isReplyCert, issueReplyCert, keyringSigningBytes, normalizeInfluence,
  publicWriteRefused, replyCertSigningBytes, sign, signSessionReply, signingBytesV3, utf8, verifyChainOffline, verifyChainV3, verifyKeyring, verifyReplyCert,
} from "@paztport/core";
import type { OfflineConfig, OfflineInput, SessionReply, V3Config, V3Input } from "@paztport/core";
import { classifySessionReply } from "../src/index.ts";
import { buildVectorsV3 } from "./vectors-v3-export.ts";

type Sections = "signingBytesV3" | "signatures" | "influence" | "rule" | "keyring" | "verify" | "offline" | "replyCert" | "sessionReply";
const committed: Record<Sections, any[]> & { keys: Record<string, { pub: string; priv: string }>; policies: any } = JSON.parse(
  readFileSync(new URL("../../../spec/vectors/v3.json", import.meta.url), "utf8"),
);

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
  const live: V3Config = { ...cfg, nonces: new NonceCache(c.nonceTtlMs), now: c.now, callMaxAgeMs: c.callMaxAgeMs, runMaxAgeMs: c.runMaxAgeMs };
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
  it("keyring", () => { for (const k of committed.keyring) expect(verifyKeyring(k.signed, committed.keys[k.policyKey].pub)).toBe(k.verifies); });
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

  it.each(committed.sessionReply.map((c: any): [string, any] => [c.name, c]))("session reply %s", (_n, c: any) => {
    const pin = committed.keys[c.pin].pub;
    const outcome = classifySessionReply(c.reply, c.request, pin, c.serverEntry, c.now);
    expect(outcome.status === "attested" ? "ATTESTED" : outcome.reason).toBe(c.expected);
    // Offline, judged at the same time, the handshake is attested exactly when the live check says so.
    expect(isAttestedSession(c.request, c.reply, pin, c.serverEntry, c.now)).toBe(c.expected === "ATTESTED");
  });

  // A configured entry named like an Object.prototype member must not find a key in a keyring that lacks it.
  it.each(["constructor", "__proto__", "toString"])("protoEntryHasNoKey %s", (entry) => {
    const good = committed.sessionReply.find((c: any) => c.name === "new form attested");
    const keys = committed.keys;
    const cert = issueReplyCert(keys["server-policy"].pub, entry, keys["mcp-entry"].pub, good.reply.serverReplyCert.notAfter, keys["server-policy"].priv);
    expect(verifyReplyCert(cert, keys["server-policy"].pub)).toBe(true);
    const { sig: _sig, ...body } = good.reply;
    const reply = signSessionReply({ ...body, serverReplyCert: cert } as Omit<SessionReply, "sig">, keys["mcp-entry"].priv);
    expect(classifySessionReply(reply, good.request, keys["server-policy"].pub, entry, good.now)).toEqual({
      status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true,
    });
    expect(isAttestedSession(good.request, reply, keys["server-policy"].pub, entry, good.now)).toBe(false);
  });

  it("keyring signing bytes and named services match the signed keyring", () => {
    for (const k of committed.keyring) {
      expect(encode(keyringSigningBytes(k.signed.policy, k.signed.services))).toBe(k.signingBytes);
      expect(encode(utf8("paztport-keyring\n" + canonicalize({ policy: k.signed.policy, services: k.signed.services })))).toBe(k.signingBytes);
      expect(k.signed.sig).toBe(k.sig);
      const named = Object.fromEntries(Object.entries(k.services as Record<string, string>).map(([svc, name]) => [svc, committed.keys[name].pub]));
      expect(k.signed.services).toEqual(named);
      expect(k.signed.policy).toBe(committed.keys[k.policyKey].pub);
    }
  });
});
