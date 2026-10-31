// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// One test per sentence of sessions-and-influence.md §Recorded handshakes, and of verification.md §Offline
// verification's recorded call, response and handshake.

import { describe, expect, it } from "vitest";
import { generateKeyPair, randomBytes } from "../../src/crypto/crypto.ts";
import { signKeyring, signKeyringOldForm } from "../../src/policy/keyring.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { signRoot, signRootOldForm } from "../../src/policy/root.ts";
import { bindResponse, newContentId, recheckResponse } from "../../src/session/attestation.ts";
import { signReplyCert } from "../../src/session/reply-cert.ts";
import { deriveSessionId, newNonce, signSessionReply, type SessionReply, type SessionRequest } from "../../src/session/session.ts";
import { bindPrompt, bindResult } from "../../src/stamp/binding.ts";
import { signStampV3 } from "../../src/stamp/stamp.ts";
import { verifyChainOffline } from "../../src/offline/verify-offline.ts";
import { callInSession, newRecordSet, recordedSession, type RecordedHandshake } from "../../src/offline/records.ts";

const ENTRY = "mcp-entry";
const NOW = 1_767_225_600_000;
/** Far past every time judged here. */
const FAR = 4_102_444_800_000;

/** Each window's `notAfter`; null signs that root or keyring in the old form. */
type Windows = { cert: number; clientRoot: number | null; clientKeyring: number | null; serverRoot: number | null; serverKeyring: number | null };

/**
 * A recorded handshake: an attested reply in the entry-key form (signed by the entry's certified key, carrying the
 * server keyring's signature and the certificate) or the policy-key form, every window FAR unless given.
 */
function handshake(o: { form?: "entry-key" | "policy-key"; windows?: Partial<Windows>; legacy?: boolean; status?: "attested" | "unsafe" } = {}) {
  const w: Windows = { cert: FAR, clientRoot: FAR, clientKeyring: FAR, serverRoot: FAR, serverKeyring: FAR, ...o.windows };
  const form = o.form ?? "entry-key";
  const clientPolicy = generateKeyPair();
  const serverPolicy = generateKeyPair();
  const entry = generateKeyPair();
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const clientTree = buildTree([{ salt: randomBytes(16), path: "session/pi/orders" }], 4, "c1");
  const serverTree = buildTree([{ salt: randomBytes(16), path: "mcp-entry/tools" }], 4, "s1");
  const clientRoot = w.clientRoot === null ? signRootOldForm(clientTree.root, "c1", clientPolicy.privateKey) : signRoot(clientTree.root, "c1", clientPolicy.privateKey, w.clientRoot);
  const clientServices = { session: session.publicKey, pi: pi.publicKey };
  const clientRing =
    w.clientKeyring === null
      ? signKeyringOldForm(clientServices, clientPolicy.publicKey, clientPolicy.privateKey)
      : signKeyring(clientServices, clientPolicy.publicKey, clientPolicy.privateKey, w.clientKeyring);
  const request: SessionRequest = {
    clientRoot,
    clientPolicyKey: clientPolicy.publicKey,
    clientKeyring: clientRing.services,
    clientKeyringSig: clientRing.sig,
    ...(clientRing.notAfter === undefined ? {} : { clientKeyringNotAfter: clientRing.notAfter }),
    nonce: newNonce(),
  };
  if (o.legacy === true) {
    delete (request as Partial<SessionRequest>).clientKeyringSig;
    delete request.clientKeyringNotAfter;
  }
  const serverRoot = w.serverRoot === null ? signRootOldForm(serverTree.root, "s1", serverPolicy.privateKey) : signRoot(serverTree.root, "s1", serverPolicy.privateKey, w.serverRoot);
  const serverServices = { [ENTRY]: entry.publicKey, tools: entry.publicKey };
  const serverRing =
    w.serverKeyring === null
      ? signKeyringOldForm(serverServices, serverPolicy.publicKey, serverPolicy.privateKey)
      : signKeyring(serverServices, serverPolicy.publicKey, serverPolicy.privateKey, w.serverKeyring);
  const serverNonce = newNonce();
  const entryKeyFields =
    form === "entry-key"
      ? {
          serverKeyringSig: serverRing.sig,
          ...(serverRing.notAfter === undefined ? {} : { serverKeyringNotAfter: serverRing.notAfter }),
          serverReplyCert: signReplyCert(serverPolicy.publicKey, ENTRY, entry.publicKey, w.cert, serverPolicy.privateKey),
        }
      : {};
  const reply = signSessionReply(
    {
      serverRoot,
      serverPolicyKey: serverPolicy.publicKey,
      serverKeyring: serverRing.services,
      ...entryKeyFields,
      nonce: serverNonce,
      sess: deriveSessionId(clientRoot.sig, serverRoot.sig, request.nonce, serverNonce, request),
      status: o.status ?? "attested",
      disabled: [],
    },
    form === "entry-key" ? entry.privateKey : serverPolicy.privateKey,
  );
  const recorded: RecordedHandshake = { request, reply, pin: serverPolicy.publicKey, serverEntry: ENTRY };
  return { recorded, request, reply, clientPolicy, serverPolicy, entry, session, pi, clientTree, serverTree };
}

/** The handshake with `reply` replaced by one re-signed by the entry key over `over`. */
function resigned(h: ReturnType<typeof handshake>, over: Partial<SessionReply>): RecordedHandshake {
  const { sig: _sig, ...body } = h.reply;
  return { ...h.recorded, reply: signSessionReply({ ...body, ...over }, h.entry.privateKey) };
}

describe("recordedSession: what a recorded handshake opened", () => {
  // "Offline, a recorded handshake opened an attested session only when the reply's status is "attested", the reply
  // passes the client's check against the recorded pin and the server's entry service from the verifier's own
  // configuration, both roots verify against their sides' policy keys, and the keyring signature verifies."
  it("attestedOnlyWhenEveryCheckHolds", () => {
    const h = handshake();
    expect(recordedSession(h.recorded)).toMatchObject({ attested: true, legacy: false });
    expect(recordedSession(handshake({ status: "unsafe" }).recorded).attested).toBe(false);
    expect(recordedSession({ ...h.recorded, pin: generateKeyPair().publicKey }).attested).toBe(false);
    expect(recordedSession({ ...h.recorded, serverEntry: "tools" }).attested).toBe(false);
    const badClientRoot = { ...h.request, clientRoot: { ...h.request.clientRoot!, sig: signRoot(h.clientTree.root, "c1", generateKeyPair().privateKey, FAR).sig } };
    expect(recordedSession({ ...h.recorded, request: badClientRoot }).attested).toBe(false);
    const badRing = { ...h.request, clientKeyringSig: signKeyring(h.request.clientKeyring, h.request.clientPolicyKey, generateKeyPair().privateKey, FAR).sig };
    expect(recordedSession({ ...h.recorded, request: badRing }).attested).toBe(false);
  });

  it("theEntryIsTheVerifiersNeverTheRecords", () => {
    const h = handshake();
    expect(recordedSession(resigned(h, { serverEntry: "tools" } as Partial<SessionReply>)).attested).toBe(true);
    expect(recordedSession({ ...resigned(h, {}), serverEntry: "tools" }).attested).toBe(false);
  });

  // "When the request has no clientKeyringSig field at all, it is legacy: the keyring check is skipped, and the
  // result is marked legacy."
  it("aRequestWithNoKeyringSignatureIsLegacy", () => {
    const h = handshake({ legacy: true });
    expect(recordedSession(h.recorded)).toMatchObject({ attested: true, legacy: true });
    // a failure is never marked
    expect(recordedSession({ ...h.recorded, pin: generateKeyPair().publicKey })).toMatchObject({ attested: false, legacy: false });
    // nothing signs a legacy request's keyring window
    expect(recordedSession({ ...h.recorded, request: { ...h.request, clientKeyringNotAfter: FAR } }).attested).toBe(false);
  });

  // "The handshake record carries no signed time, so it is judged at each call's recorded time … One session can
  // therefore be attested for the calls recorded up to its limits and not for those after them."
  // "Its limits are the certificate's notAfter (entry-key form) and the notAfter of each root and keyring in the new
  // form, the client's and the server's."
  it.each(["cert", "clientRoot", "clientKeyring", "serverRoot", "serverKeyring"] as const)("attestedUpToThe%sWindow", (which) => {
    const s = recordedSession(handshake({ windows: { [which]: NOW } }).recorded);
    expect(s.attestedAt(NOW - 1)).toBe(true);
    expect(s.attestedAt(NOW)).toBe(true);
    expect(s.attestedAt(NOW + 1)).toBe(false);
    expect(s.attested).toBe(true);
  });

  // "A verifier asking whether the session was attested at all judges it at the earliest of those, since each is an
  // upper bound."
  it("attestedAtAllIsJudgedAtTheEarliestLimit", () => {
    const s = recordedSession(handshake({ windows: { cert: NOW + 5, clientRoot: NOW + 3, serverKeyring: NOW + 4 } }).recorded);
    expect(s.attested).toBe(true);
    expect(s.attestedAt(NOW + 3)).toBe(true);
    expect(s.attestedAt(NOW + 4)).toBe(false);
    // a window moved earlier in the record fails its signature at the earliest limit, so the session is attested at no time
    const h = handshake();
    expect(recordedSession({ ...h.recorded, request: { ...h.request, clientKeyringNotAfter: 0 } }).attested).toBe(false);
  });

  // "A policy-key reply over old-form material has no limit, and is judged the same at any time."
  it("aPolicyKeyReplyOverOldFormMaterialHasNoLimit", () => {
    const h = handshake({ form: "policy-key", windows: { clientRoot: null, clientKeyring: null, serverRoot: null, serverKeyring: null } });
    const s = recordedSession(h.recorded);
    expect(s.attested).toBe(true);
    expect(s.attestedAt(0)).toBe(true);
    expect(s.attestedAt(Number.MAX_SAFE_INTEGER)).toBe(true);
  });

  // "A recorded response is limited only by the server's root window and, in the entry-key form, the server
  // keyring's: the client's windows and the certificate do not limit it."
  it("aResponseIsLimitedOnlyByTheServersRootAndEntryKeyKeyring", () => {
    expect(recordedSession(handshake({ windows: { serverRoot: NOW + 2, serverKeyring: NOW + 1 } }).recorded).responseNotAfter).toBe(NOW + 1);
    expect(recordedSession(handshake({ windows: { serverRoot: NOW + 1, serverKeyring: NOW + 2 } }).recorded).responseNotAfter).toBe(NOW + 1);
    expect(recordedSession(handshake({ windows: { cert: NOW, clientRoot: NOW, clientKeyring: NOW } }).recorded).responseNotAfter).toBe(FAR);
    // the policy-key form carries no keyring signature, so no keyring window
    expect(recordedSession(handshake({ form: "policy-key", windows: { serverRoot: NOW + 2 } }).recorded).responseNotAfter).toBe(NOW + 2);
    // an old-form root or keyring sets no limit: 2^53 − 1 when neither has a window
    expect(recordedSession(handshake({ windows: { serverRoot: null, serverKeyring: null } }).recorded).responseNotAfter).toBe(Number.MAX_SAFE_INTEGER);
    expect(recordedSession(handshake({ windows: { serverRoot: null, serverKeyring: NOW } }).recorded).responseNotAfter).toBe(NOW);
  });

  // "There is no client pin offline. The server's signed "attested" reply … is its statement that it pinned them."
  it("thereIsNoClientPinOffline", () => {
    // nothing here names the client policy key: the reply alone vouches for it
    const h = handshake();
    expect(Object.keys(h.recorded).sort()).toEqual(["pin", "reply", "request", "serverEntry"]);
    expect(recordedSession(h.recorded).attested).toBe(true);
  });

  // "Offline, a root or keyring in the old form is accepted, as recorded evidence holds it: it sets no limit, and the
  // session is not marked legacy for it (only a request with no clientKeyringSig is)."
  it("oldFormMaterialIsAcceptedSetsNoLimitAndIsNotLegacy", () => {
    const s = recordedSession(handshake({ windows: { clientRoot: null, clientKeyring: null, serverRoot: null, serverKeyring: null } }).recorded);
    expect(s).toMatchObject({ attested: true, legacy: false });
    // only the certificate limits it
    expect(s.attestedAt(FAR)).toBe(true);
    expect(s.attestedAt(FAR + 1)).toBe(false);
  });

  // "A root or keyring in the new form is judged at the record's time, on both sides, as above, but only after its own
  // signature has verified … so one moved or dropped in the record fails offline too, and an inherited one never counts."
  it("aMovedOrDroppedWindowFailsItsSignature", () => {
    const h = handshake({ windows: { clientRoot: NOW } });
    expect(recordedSession({ ...h.recorded, request: { ...h.request, clientRoot: { ...h.request.clientRoot!, notAfter: FAR } } }).attested).toBe(false);
    const { notAfter: _w, ...dropped } = h.request.clientRoot!;
    expect(recordedSession({ ...h.recorded, request: { ...h.request, clientRoot: dropped } }).attested).toBe(false);
    expect(recordedSession(resigned(handshake(), { serverKeyringNotAfter: FAR + 1 })).attested).toBe(false);
    const { clientKeyringNotAfter: _k, ...noWindow } = h.request;
    expect(recordedSession({ ...h.recorded, request: Object.assign(Object.create({ clientKeyringNotAfter: FAR }), noWindow) }).attested).toBe(false);
  });

  it("neverThrows", () => {
    const h = handshake();
    const broken = { ...h.recorded, reply: null } as unknown as RecordedHandshake;
    expect(recordedSession(broken)).toMatchObject({ attested: false, legacy: false });
    expect(recordedSession(broken).attestedAt(NOW)).toBe(false);
  });
});

/** A two-stamp call chain in `sess`, its last stamp at `ts`, signed by the handshake's client keys. */
function call(h: ReturnType<typeof handshake>, ts: number, sess = h.reply.sess) {
  const origin = signStampV3({ svc: "session", inst: "pi-1", rid: "rid-1", ts: ts - 1, sess, rcv: "pi", bind: bindPrompt("p"), infl: "", prev: "" }, h.session.privateKey);
  const hop = signStampV3({ svc: "pi", inst: "pi-1", rid: "rid-1", ts, sess, rcv: "orders", bind: "call-bind", infl: "", prev: origin.sig }, h.pi.privateKey);
  return [origin, hop];
}

/** The offline check of a call recorded in `h`'s session: the client's keyring and root from the request, and the session id. */
function checkCall(h: ReturnType<typeof handshake>, chain: unknown, ts: number, spent: Set<string>) {
  return verifyChainOffline(
    { stamps: chain, expectedBind: "call-bind", influence: [], proof: h.clientTree.proofFor("session/pi/orders"), receiver: "orders", receiverInRoute: true, rid: "rid-1", recordedTs: { last: ts }, prompt: "p" },
    { keyring: h.request.clientKeyring, root: h.clientTree.root, rootId: "c1", allowedOrigins: ["session"], sess: h.reply.sess, seen: spent, nonceKey: "rid-1|call-1|req" },
  );
}

describe("callInSession: a recorded call counts in its session only up to the session's limits", () => {
  // "The call counts in its session only up to the session's limits, judged at the last stamp's ts. A call that
  // otherwise verifies, in a session whose recorded handshake is attested, but whose last stamp's ts is past one of the
  // session's limits, is OUTSIDE_SESSION."
  it("aCallPastALimitIsOutsideSession", () => {
    const h = handshake({ windows: { cert: NOW } });
    const s = recordedSession(h.recorded);
    for (const [ts, want] of [[NOW - 1, "OK"], [NOW, "OK"], [NOW + 1, "OUTSIDE_SESSION"]] as const) {
      const v = checkCall(h, call(h, ts), ts, new Set());
      expect(v.reason).toBe("OK");
      expect(callInSession(s, v.reason, ts)).toBe(want);
    }
  });

  it("aCallThatFailsKeepsItsOwnResult", () => {
    const s = recordedSession(handshake({ windows: { cert: NOW } }).recorded);
    expect(callInSession(s, "BAD_SIGNATURE", NOW + 1)).toBe("BAD_SIGNATURE");
    expect(callInSession(s, "PATH_NOT_ALLOWED", NOW + 1)).toBe("PATH_NOT_ALLOWED");
  });

  it("aSessionNotAttestedGivesNoResult", () => {
    const h = handshake({ status: "unsafe" });
    expect(callInSession(recordedSession(h.recorded), "OK", NOW)).toBeUndefined();
  });
});

describe("newRecordSet: replay across a record set", () => {
  // "The nonce key has not been spent anywhere in the record set (REPLAY)."
  it("callsAndLocalStepsShareOneSetOfSpentKeys", () => {
    const h = handshake();
    const records = newRecordSet();
    expect(checkCall(h, call(h, NOW), NOW, records.spent).reason).toBe("OK");
    expect(records.spent.has("rid-1|call-1|req")).toBe(true);
    // a copy recorded much later is still a replay: the set never forgets
    expect(checkCall(h, call(h, FAR), FAR, records.spent).reason).toBe("REPLAY");
  });

  it("aRepeatedSessionRecordResetsNeitherCache", () => {
    const h = handshake();
    const records = newRecordSet();
    const first = recordedSession(h.recorded);
    expect(callInSession(first, checkCall(h, call(h, NOW), NOW, records.spent).reason, NOW)).toBe("OK");
    const respond = response(h);
    const cfg = { ...responseConfig(h, records), policyNotAfter: first.responseNotAfter };
    expect(recheckResponse(respond.att, respond.body, RESPONSE_CALL, cfg).result.reason).toBe("OK");
    // the same handshake recorded again
    const again = recordedSession(h.recorded);
    expect(again.attested).toBe(true);
    expect(callInSession(again, checkCall(h, call(h, NOW), NOW, records.spent).reason, NOW)).toBe("REPLAY");
    expect(recheckResponse(respond.att, respond.body, RESPONSE_CALL, { ...cfg, policyNotAfter: again.responseNotAfter }).result.reason).toBe("REPLAY");
  });

  // "A recorded response: … one nonce cache that never forgets across the record set."
  it("theResponseCacheNeverForgets", () => {
    const h = handshake();
    const records = newRecordSet();
    const respond = response(h);
    const cfg = { ...responseConfig(h, records), policyNotAfter: recordedSession(h.recorded).responseNotAfter };
    expect(recheckResponse(respond.att, respond.body, RESPONSE_CALL, cfg).result.reason).toBe("OK");
    expect(recheckResponse(respond.att, respond.body, RESPONSE_CALL, cfg).result.reason).toBe("REPLAY");
    // a live cache forgets a key after its TTL; this one still holds it at the end of time
    expect(records.responseNonces.seenBefore("rid-1|call-1|resp", Number.MAX_SAFE_INTEGER)).toBe(true);
  });

  // "Check 0 runs at that time, with the policyNotAfter the client used … So a response recorded after the server's
  // new-form material expired is POLICY_EXPIRED."
  it("aResponsePastTheServersMaterialIsPolicyExpired", () => {
    const h = handshake({ windows: { serverRoot: NOW + 10 } });
    const s = recordedSession(h.recorded);
    const respond = response(h);
    const cfg = { ...responseConfig(h, newRecordSet()), policyNotAfter: s.responseNotAfter };
    expect(recheckResponse(respond.att, respond.body, RESPONSE_CALL, { ...cfg, now: NOW + 11 }).result.reason).toBe("POLICY_EXPIRED");
    expect(recheckResponse(respond.att, respond.body, RESPONSE_CALL, cfg).result.reason).toBe("OK");
  });
});

const RESPONSE_CALL = { rid: "rid-1", toolCallId: "call-1", receiver: "pi" };

/** The server's signed response to call-1 in `h`'s session, stamped at NOW. */
function response(h: ReturnType<typeof handshake>) {
  const body: Record<string, unknown> = { content: [{ type: "text", text: "done" }] };
  const resultHash = bindResult(body);
  const labels = [{ cls: "third-party" as const, cid: newContentId() }];
  const s0 = signStampV3({ svc: ENTRY, inst: "e-1", rid: "rid-1", ts: NOW, sess: h.reply.sess, rcv: "tools", bind: "b0", infl: "", prev: "" }, h.entry.privateKey);
  const s1 = signStampV3({ svc: "tools", inst: "t-1", rid: "rid-1", ts: NOW, sess: h.reply.sess, rcv: "pi", bind: bindResponse(resultHash, "call-1", labels), infl: "", prev: s0.sig }, h.entry.privateKey);
  return { body, att: { chain: [s0, s1], proof: h.serverTree.proofFor("mcp-entry/tools"), labels, resultHash } };
}

/** The live check's config for a response recorded in `h`'s session, against the record set's response cache. */
function responseConfig(h: ReturnType<typeof handshake>, records: ReturnType<typeof newRecordSet>) {
  return { keyring: h.reply.serverKeyring, root: h.serverTree.root, rootId: "s1", allowedOrigins: [ENTRY], sess: h.reply.sess, nonces: records.responseNonces, now: NOW };
}
