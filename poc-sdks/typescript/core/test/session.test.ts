// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../src/b64url.ts";
import { generateKeyPair, randomBytes, sign, utf8, verify } from "../src/crypto.ts";
import { canonicalize } from "../src/jcs.ts";
import { signKeyring, signKeyringOldForm } from "../src/keyring.ts";
import { issueReplyCert } from "../src/reply-cert.ts";
import { signRoot, signRootOldForm, verifyRoot, type SignedRoot } from "../src/root.ts";
import { isCurrent } from "../src/validity.ts";
import {
  deriveSessionId,
  isAttestedSession,
  isLegacySessionRequest,
  newNonce,
  sessionStatus,
  signSessionReply,
  verifySessionReply,
  type LegacySessionRequest,
  type SessionReply,
  type SessionRequest,
} from "../src/session.ts";

const ENTRY = "mcp-entry";
const NOW = 1_767_225_600_000;
/** Every live root and keyring here is in the new form, valid until 2100-01-01. */
const NOT_AFTER = 4_102_444_800_000;

/** New-form roots and keyring on both sides; `oldForm` signs them all in the old form instead, as recorded evidence holds. */
function world(oldForm = false) {
  const clientPolicy = generateKeyPair();
  const serverPolicy = generateKeyPair();
  const clientRootBytes = randomBytes(32);
  const serverRootBytes = randomBytes(32);
  const root = (bytes: Uint8Array, id: string, key: string) => (oldForm ? signRootOldForm(bytes, id, key) : signRoot(bytes, id, key, NOT_AFTER));
  const clientRoot = root(clientRootBytes, "v1", clientPolicy.privateKey);
  const serverRoot = root(serverRootBytes, "v2", serverPolicy.privateKey);
  const ring = oldForm
    ? signKeyringOldForm({ session: "k" }, clientPolicy.publicKey, clientPolicy.privateKey)
    : signKeyring({ session: "k" }, clientPolicy.publicKey, clientPolicy.privateKey, NOT_AFTER);
  const req: SessionRequest = {
    clientRoot,
    clientPolicyKey: clientPolicy.publicKey,
    clientKeyring: ring.services,
    clientKeyringSig: ring.sig,
    ...(oldForm ? {} : { clientKeyringNotAfter: NOT_AFTER }),
    nonce: newNonce(),
  };
  const body = (): Omit<SessionReply, "sig"> => {
    const serverNonce = newNonce();
    return {
      serverRoot,
      serverPolicyKey: serverPolicy.publicKey,
      serverKeyring: { "mcp-entry": "k2" },
      nonce: serverNonce,
      sess: deriveSessionId(req.clientRoot?.sig ?? null, serverRoot.sig, req.nonce, serverNonce, req),
      status: "attested",
      disabled: [],
    };
  };
  const pinned = [clientPolicy.publicKey];
  return { clientPolicy, serverPolicy, clientRootBytes, serverRootBytes, clientRoot, serverRoot, req, body, pinned };
}

describe("sessionStatus", () => {
  type World = ReturnType<typeof world>;
  /** sessionStatus at `now` (NOW) against the server's own root and keyring window (NOT_AFTER unless given). */
  const status = (
    w: World,
    req: SessionRequest = w.req,
    o: { serverRoot?: SignedRoot | null; serverKeyringNotAfter?: number | undefined; pinned?: string[]; now?: number } = {},
  ) =>
    sessionStatus(
      req,
      Object.hasOwn(o, "serverRoot") ? o.serverRoot! : w.serverRoot,
      Object.hasOwn(o, "serverKeyringNotAfter") ? o.serverKeyringNotAfter : NOT_AFTER,
      w.serverPolicy.publicKey,
      o.pinned ?? w.pinned,
      o.now ?? NOW,
    );
  /** The request with the client's root re-signed until `notAfter`. */
  const withClientRoot = (w: World, notAfter: number): SessionRequest => ({ ...w.req, clientRoot: signRoot(w.clientRootBytes, "v1", w.clientPolicy.privateKey, notAfter) });
  /** The request with the client's keyring re-signed until `notAfter`, the window beside it. */
  const withClientKeyring = (w: World, notAfter: number): SessionRequest => {
    const ring = signKeyring(w.req.clientKeyring, w.clientPolicy.publicKey, w.clientPolicy.privateKey, notAfter);
    return { ...w.req, clientKeyringSig: ring.sig, clientKeyringNotAfter: notAfter };
  };

  it("bothRootsAttested", () => {
    expect(status(world())).toBe("attested");
  });
  it("missingClientRootUnsafe", () => {
    const w = world();
    expect(status(w, { ...w.req, clientRoot: null })).toBe("unsafe");
  });
  it("clientRootBadSigUnsafe", () => {
    const w = world();
    expect(status(w, { ...w.req, clientRoot: { ...w.clientRoot, sig: encode(randomBytes(64)) } })).toBe("unsafe");
  });
  it("missingServerRootUnsafe", () => {
    const w = world();
    expect(status(w, w.req, { serverRoot: null })).toBe("unsafe");
  });
  it("aClientPolicyKeyThatIsNotPinnedIsUnsafe", () => {
    const w = world();
    expect(status(w, w.req, { pinned: [generateKeyPair().publicKey] })).toBe("unsafe");
  });
  it("noPinnedClientKeysIsUnsafe", () => {
    const w = world();
    expect(status(w, w.req, { pinned: [] })).toBe("unsafe");
  });
  it("aKeyringAlteredSinceSigningIsUnsafe", () => {
    const w = world();
    expect(status(w, { ...w.req, clientKeyring: { session: "evil" } })).toBe("unsafe");
  });
  it("anEmptyPinNeverMatches", () => {
    const w = world();
    expect(status(w, w.req, { pinned: [""] })).toBe("unsafe");
    expect(status(w, { ...w.req, clientPolicyKey: "" }, { pinned: [""] })).toBe("unsafe");
  });
  it("anEmptyKeyringSignatureIsUnsafe", () => {
    const w = world();
    expect(status(w, { ...w.req, clientKeyringSig: "" })).toBe("unsafe");
  });
  it("clientKeyringNotAfterIsCoveredByTheKeyringSignature", () => {
    const w = world();
    expect(w.req.clientKeyringNotAfter).toBe(NOT_AFTER);
    expect(status(w)).toBe("attested");
    // moved or dropped in transit, the keyring signature fails in the form the request now claims
    expect(status(w, { ...w.req, clientKeyringNotAfter: NOT_AFTER + 1 })).toBe("unsafe");
    const { clientKeyringNotAfter: _window, ...dropped } = w.req;
    expect(status(w, dropped)).toBe("unsafe");
    // a present value that is not an integer in range never reads as the old form
    for (const bad of [1.5, -1, 2 ** 53, "x", null, true, {}, []]) {
      expect(status(w, { ...w.req, clientKeyringNotAfter: bad } as unknown as SessionRequest), String(bad)).toBe("unsafe");
    }
  });
  it("anExpiredClientRootOrKeyringIsUnsafe", () => {
    const w = world();
    // each is current up to and including its notAfter, and not a millisecond after
    expect(status(w, withClientRoot(w, NOW))).toBe("attested");
    expect(status(w, withClientRoot(w, NOW), { now: NOW + 1 })).toBe("unsafe");
    expect(status(w, withClientKeyring(w, NOW))).toBe("attested");
    expect(status(w, withClientKeyring(w, NOW), { now: NOW + 1 })).toBe("unsafe");
    // a clock that is not a number never makes either current
    expect(status(w, w.req, { now: Number.NaN })).toBe("unsafe");
  });
  it("anOldFormClientRootOrKeyringIsUnsafe", () => {
    const w = world();
    const oldRoot = signRootOldForm(w.clientRootBytes, "v1", w.clientPolicy.privateKey);
    expect(status(w, { ...w.req, clientRoot: oldRoot })).toBe("unsafe");
    const oldRing = signKeyringOldForm(w.req.clientKeyring, w.clientPolicy.publicKey, w.clientPolicy.privateKey);
    const { clientKeyringNotAfter: _window, ...rest } = w.req;
    expect(status(w, { ...rest, clientKeyringSig: oldRing.sig })).toBe("unsafe");
    // a request whose material is all in the old form, as the TypeScript and Java servers both now refuse to attest
    // (the server's root is its own, in the new form, so the client's old form is the only reason)
    const old = world(true);
    expect(Object.hasOwn(old.req, "clientKeyringNotAfter")).toBe(false);
    const serverRoot = signRoot(old.serverRootBytes, "v2", old.serverPolicy.privateKey, NOT_AFTER);
    expect(status(old, old.req, { serverRoot })).toBe("unsafe");
    const ring = signKeyring(old.req.clientKeyring, old.clientPolicy.publicKey, old.clientPolicy.privateKey, NOT_AFTER);
    const renewed: SessionRequest = {
      ...old.req,
      clientRoot: signRoot(old.clientRootBytes, "v1", old.clientPolicy.privateKey, NOT_AFTER),
      clientKeyringSig: ring.sig,
      clientKeyringNotAfter: NOT_AFTER,
    };
    expect(status(old, renewed, { serverRoot }), "the same material in the new form").toBe("attested");
  });
  it("aClientRootWhoseWindowWasMovedIsUnsafeByItsOwnSignature", () => {
    // an expired root with its window moved on: current by the moved value, so only the root's signature stops it
    const w = world();
    const expired = withClientRoot(w, NOW - 1).clientRoot!;
    const moved: SignedRoot = { ...expired, notAfter: NOT_AFTER };
    expect(isCurrent(moved, NOW)).toBe(true);
    expect(verifyRoot(moved, w.clientPolicy.publicKey)).toBe(false);
    expect(status(w, { ...w.req, clientRoot: moved })).toBe("unsafe");
  });
  it("aServerWhoseOwnRootOrKeyringIsNotCurrentOpensEverySessionUnsafe", () => {
    const w = world();
    const serverRootUntil = (notAfter: number) => signRoot(w.serverRootBytes, "v2", w.serverPolicy.privateKey, notAfter);
    expect(status(w, w.req, { serverRoot: serverRootUntil(NOW) })).toBe("attested");
    expect(status(w, w.req, { serverRoot: serverRootUntil(NOW), now: NOW + 1 })).toBe("unsafe");
    expect(status(w, w.req, { serverKeyringNotAfter: NOW })).toBe("attested");
    expect(status(w, w.req, { serverKeyringNotAfter: NOW, now: NOW + 1 })).toBe("unsafe");
    // the old form: a root with no window, and a keyring with none
    expect(status(w, w.req, { serverRoot: signRootOldForm(w.serverRootBytes, "v2", w.serverPolicy.privateKey) })).toBe("unsafe");
    expect(status(w, w.req, { serverKeyringNotAfter: undefined })).toBe("unsafe");
    for (const bad of [1.5, -1, 2 ** 53, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(status(w, w.req, { serverKeyringNotAfter: bad }), String(bad)).toBe("unsafe");
    }
  });
  it("anInheritedClientKeyringNotAfterNeverCounts", () => {
    const w = world();
    const { clientKeyringNotAfter: _window, ...dropped } = w.req;
    const inheriting = (req: object) => Object.assign(Object.create({ clientKeyringNotAfter: NOT_AFTER }), req) as SessionRequest;
    expect(status(w, inheriting(dropped))).toBe("unsafe");
    // offline, the own-member rule stops it before any window is judged: an inherited window would make the new-form
    // signature verify
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(w.req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(isAttestedSession(inheriting(dropped), reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    // an old-form keyring is checked in the old form, whatever its prototype offers
    const old = world(true);
    const oldReply = signSessionReply(old.body(), old.serverPolicy.privateKey);
    expect(isAttestedSession(inheriting(old.req), oldReply, old.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
});

describe("isLegacySessionRequest", () => {
  it("aRequestWithoutAKeyringSignatureIsLegacy", () => {
    const w = world();
    const { clientKeyringSig: _sig, ...legacy } = w.req;
    expect(isLegacySessionRequest(legacy)).toBe(true);
    expect(isLegacySessionRequest(w.req)).toBe(false);
  });
});

describe("deriveSessionId", () => {
  const a = encode(randomBytes(64));
  const b = encode(randomBytes(64));
  const n1 = newNonce();
  const n2 = newNonce();
  const keys = { clientPolicyKey: "pk", clientKeyring: { session: "k" } };
  it("sessionIdDeterministic", () => {
    expect(deriveSessionId(a, b, n1, n2, keys)).toBe(deriveSessionId(a, b, n1, n2, keys));
  });
  it("sessionIdChangesWithEitherNonce", () => {
    const base = deriveSessionId(a, b, n1, n2, keys);
    expect(deriveSessionId(a, b, newNonce(), n2, keys)).not.toBe(base);
    expect(deriveSessionId(a, b, n1, newNonce(), keys)).not.toBe(base);
  });
  it("sessionIdChangesWithClientKeys", () => {
    const base = deriveSessionId(a, b, n1, n2, keys);
    expect(deriveSessionId(a, b, n1, n2, { ...keys, clientPolicyKey: "other" })).not.toBe(base);
    expect(deriveSessionId(a, b, n1, n2, { ...keys, clientKeyring: { session: "x" } })).not.toBe(base);
  });
  it("nullRootsNotInterchangeable", () => {
    expect(deriveSessionId(null, a, n1, n2, keys)).not.toBe(deriveSessionId(a, null, n1, n2, keys));
  });
  it("badLengthsThrow", () => {
    expect(() => deriveSessionId(encode(randomBytes(63)), b, n1, n2, keys)).toThrow();
    expect(() => deriveSessionId(a, encode(randomBytes(65)), n1, n2, keys)).toThrow();
    expect(() => deriveSessionId(a, b, encode(randomBytes(15)), n2, keys)).toThrow();
    expect(() => deriveSessionId(a, b, n1, encode(randomBytes(17)), keys)).toThrow();
  });
  it("theKeyringWindowIsNotInTheSessionId", () => {
    const w = world();
    const { clientKeyringNotAfter: _window, ...old } = w.req;
    const sess = (req: SessionRequest) => deriveSessionId(w.clientRoot.sig, w.serverRoot.sig, n1, n2, req);
    expect(sess(w.req)).toBe(sess(old));
    expect(sess({ ...w.req, clientKeyringNotAfter: NOT_AFTER + 1 })).toBe(sess(old));
  });
  it("nonceIs16Bytes", () => {
    expect(newNonce().length).toBe(22);
  });
});

describe("session reply", () => {
  it("replyVerifies", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("replyTamperedStatusFails", () => {
    const w = world();
    const reply = signSessionReply({ ...w.body(), status: "unsafe" }, w.serverPolicy.privateKey);
    expect(verifySessionReply({ ...reply, status: "attested" }, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("replyWrongPinnedKeyFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, generateKeyPair().publicKey, ENTRY, NOW)).toBe(false);
  });
  it("replySessMismatchFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, { ...w.req, nonce: newNonce() }, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("clientKeyringSwapFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, { ...w.req, clientKeyring: { session: "evil" } }, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(verifySessionReply(reply, { ...w.req, clientPolicyKey: generateKeyPair().publicKey }, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("attestedWithNullRootRejected", () => {
    const w = world();
    const noServer = signSessionReply({ ...w.body(), serverRoot: null, sess: deriveSessionId(w.clientRoot.sig, null, w.req.nonce, w.body().nonce, w.req) }, w.serverPolicy.privateKey);
    expect(verifySessionReply(noServer, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    const body = w.body();
    const noClientReq = { ...w.req, clientRoot: null };
    const sess = deriveSessionId(null, w.serverRoot.sig, noClientReq.nonce, body.nonce, noClientReq);
    const reply = signSessionReply({ ...body, sess }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, noClientReq, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("nullServerRootReplyVerifies", () => {
    const w = world();
    const body = w.body();
    const sess = deriveSessionId(w.clientRoot.sig, null, w.req.nonce, body.nonce, w.req);
    const reply = signSessionReply({ ...body, serverRoot: null, sess, status: "unsafe" }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("replyTamperedKeyringOrDisabledFails", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply({ ...reply, serverKeyring: { "mcp-entry": "evil" } }, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(verifySessionReply({ ...reply, disabled: ["x"] }, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("replyBadServerRootFails", () => {
    const w = world();
    const bad = { ...w.serverRoot, sig: encode(randomBytes(64)) };
    const reply = signSessionReply({ ...w.body(), serverRoot: bad }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("replySignatureIsDomainSeparated", () => {
    const w = world();
    const body = w.body();
    const reply = signSessionReply(body, w.serverPolicy.privateKey);
    const prefixed = utf8("paztport-session-reply\n" + canonicalize(body));
    expect(verify(w.serverPolicy.publicKey, prefixed, decode(reply.sig))).toBe(true);
    // a signature over the bare canonical body (no domain prefix) is not accepted
    const bare = encode(sign(w.serverPolicy.privateKey, utf8(canonicalize(body))));
    expect(verifySessionReply({ ...reply, sig: bare }, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("signSessionReplyIgnoresStraySig", () => {
    const w = world();
    const body = w.body();
    const clean = signSessionReply(body, w.serverPolicy.privateKey);
    const stray = signSessionReply({ ...body, sig: "stray" } as Omit<SessionReply, "sig">, w.serverPolicy.privateKey);
    expect(stray.sig).not.toBe("stray");
    expect(stray).toEqual(clean); // Ed25519 is deterministic: same body, same signature
    expect(verifySessionReply(stray, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("aServerRootThatIsNotCurrentFailsLiveInThePolicyKeyForm", () => {
    const w = world();
    const at = (root: SignedRoot) => {
      const body = { ...w.body(), serverRoot: root };
      const sess = deriveSessionId(w.clientRoot.sig, root.sig, w.req.nonce, body.nonce, w.req);
      return signSessionReply({ ...body, sess }, w.serverPolicy.privateKey);
    };
    const untilNow = at(signRoot(w.serverRootBytes, "v2", w.serverPolicy.privateKey, NOW));
    expect(verifySessionReply(untilNow, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(verifySessionReply(untilNow, w.req, w.serverPolicy.publicKey, ENTRY, NOW + 1)).toBe(false);
    expect(verifySessionReply(untilNow, w.req, w.serverPolicy.publicKey, ENTRY, Number.NaN)).toBe(false);
    const oldRoot = at(signRootOldForm(w.serverRootBytes, "v2", w.serverPolicy.privateKey));
    expect(verifySessionReply(oldRoot, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    // offline, old forms are accepted and a new-form lifetime is judged at the record's time
    expect(isAttestedSession(w.req, untilNow, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(isAttestedSession(w.req, untilNow, w.serverPolicy.publicKey, ENTRY, NOW + 1)).toBe(false);
    expect(isAttestedSession(w.req, oldRoot, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    // the old-form server root sets no limit: only the client's windows (NOT_AFTER) do
    expect(isAttestedSession(w.req, oldRoot, w.serverPolicy.publicKey, ENTRY, NOT_AFTER)).toBe(true);
    expect(isAttestedSession(w.req, oldRoot, w.serverPolicy.publicKey, ENTRY, NOT_AFTER + 1)).toBe(false);
  });
  it("anUnsafeReplyIsJudgedTheSame", () => {
    // a degraded server says "unsafe" over its expired root; the client takes its replacement path either way
    const w = world();
    const root = signRoot(w.serverRootBytes, "v2", w.serverPolicy.privateKey, NOW);
    const body = { ...w.body(), serverRoot: root, status: "unsafe" as const, disabled: ["x"] };
    const reply = signSessionReply({ ...body, sess: deriveSessionId(w.clientRoot.sig, root.sig, w.req.nonce, body.nonce, w.req) }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW + 1)).toBe(false);
  });
  it("aServerKeyringNotAfterInThePolicyKeyFormFails", () => {
    // a keyring window with no keyring signature beside it, live and offline, like either form field without the other
    const w = world();
    const reply = signSessionReply({ ...w.body(), serverKeyringNotAfter: NOT_AFTER }, w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession(w.req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
});

describe("isAttestedSession", () => {
  it("anAttestedReplyWithBothRootsIsAttested", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(w.req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("anyFlawIsNotAttested", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    // another pin, a tampered reply, an unsafe one
    expect(isAttestedSession(w.req, reply, generateKeyPair().publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession(w.req, { ...reply, sess: "AAAA" }, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    const unsafe = signSessionReply({ ...w.body(), status: "unsafe" }, w.serverPolicy.privateKey);
    expect(isAttestedSession(w.req, unsafe, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    // the reply binds the client root's signature, not its contents: those must verify against the client policy key
    const swapped = { ...w.req, clientRoot: { ...w.clientRoot, root: encode(randomBytes(32)) } };
    expect(isAttestedSession(swapped, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    // no client root
    const noClient = { ...w.req, clientRoot: null };
    const body = w.body();
    const sess = deriveSessionId(null, w.serverRoot.sig, noClient.nonce, body.nonce, noClient);
    expect(isAttestedSession(noClient, signSessionReply({ ...body, sess, status: "unsafe" }, w.serverPolicy.privateKey), w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    // what a recorded file may hold instead of a reply
    expect(isAttestedSession(w.req, {} as SessionReply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("aV3RequestWhoseKeyringSignatureFailsIsNotAttested", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    // the session id binds the keyring but not its signature, so only the keyring check catches this
    const forged = signKeyring({ session: "k" }, w.clientPolicy.publicKey, generateKeyPair().privateKey, NOT_AFTER).sig;
    expect(isAttestedSession({ ...w.req, clientKeyringSig: forged }, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession({ ...w.req, clientKeyringSig: "" }, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("aTamperedClientKeyringNotAfterIsNotAttested", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(w.req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    // the session id does not bind the window, so only the keyring signature catches it
    expect(isAttestedSession({ ...w.req, clientKeyringNotAfter: NOT_AFTER + 1 }, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    const { clientKeyringNotAfter: _window, ...dropped } = w.req;
    expect(isAttestedSession(dropped, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("recordedOldFormMaterialIsStillAttested", () => {
    // old forms fail live and are accepted offline: live and offline do not share the refusal
    const w = world(true);
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession(w.req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("aLegacyRequestWithAnAttestedReplyIsAttested", () => {
    const w = world();
    const { clientKeyringSig: _sig, clientKeyringNotAfter: _window, ...legacy } = w.req;
    const req: LegacySessionRequest = legacy;
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("aLegacyRequestCarryingAKeyringWindowIsNotAttested", () => {
    // no signature covers the window, so it could have been added or moved by anyone holding the file
    const w = world();
    const { clientKeyringSig: _sig, ...legacy } = w.req;
    const req: LegacySessionRequest = legacy;
    expect(Object.hasOwn(req, "clientKeyringNotAfter")).toBe(true);
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession({ ...req, clientKeyringNotAfter: NOW - 1 }, reply, w.serverPolicy.publicKey, ENTRY, NOW - 2)).toBe(false);
  });
  it("aKeyringSignatureThatIsPresentButNotAStringIsNotLegacy", () => {
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    for (const sig of [null, 1]) {
      const req = { ...w.req, clientKeyringSig: sig } as unknown as SessionRequest;
      expect(isLegacySessionRequest(req), String(sig)).toBe(false);
      expect(isAttestedSession(req, reply, w.serverPolicy.publicKey, ENTRY, NOW), String(sig)).toBe(false);
    }
  });
});

describe("the entry key form", () => {
  /**
   * A reply signed by mcp-entry's key, with the server keyring's signature and window (until `keyringNotAfter`,
   * NOT_AFTER by default) and a certificate valid until NOW + 1000. `oldForm` signs every root and keyring in the
   * old form; `oldFormKeyring` only the server keyring, with no `serverKeyringNotAfter`.
   */
  function entryWorld(o: { oldForm?: boolean; oldFormKeyring?: boolean; keyringNotAfter?: number } = {}) {
    const w = world(o.oldForm ?? false);
    const oldRing = (o.oldForm ?? false) || (o.oldFormKeyring ?? false);
    const ringNotAfter = o.keyringNotAfter ?? NOT_AFTER;
    const entry = generateKeyPair();
    const services = { "mcp-entry": entry.publicKey, "github-tools": generateKeyPair().publicKey };
    const ring = oldRing
      ? signKeyringOldForm(services, w.serverPolicy.publicKey, w.serverPolicy.privateKey)
      : signKeyring(services, w.serverPolicy.publicKey, w.serverPolicy.privateKey, ringNotAfter);
    const cert = issueReplyCert(w.serverPolicy.publicKey, ENTRY, entry.publicKey, NOW + 1000, w.serverPolicy.privateKey);
    const body: Omit<SessionReply, "sig"> = {
      ...w.body(), serverKeyring: services, serverKeyringSig: ring.sig, ...(oldRing ? {} : { serverKeyringNotAfter: ringNotAfter }), serverReplyCert: cert,
    };
    return { ...w, entry, body, reply: signSessionReply(body, entry.privateKey) };
  }
  it("replySignedByTheCertifiedEntryKeyVerifies", () => {
    const w = entryWorld();
    expect(verifySessionReply(w.reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("serverKeyringNotAfterIsCoveredByTheKeyringSignature", () => {
    const w = entryWorld();
    const verifies = (body: Omit<SessionReply, "sig">) => verifySessionReply(signSessionReply(body, w.entry.privateKey), w.req, w.serverPolicy.publicKey, ENTRY, NOW);
    expect(w.reply.serverKeyringNotAfter).toBe(NOT_AFTER);
    expect(verifies(w.body)).toBe(true);
    // the entry key signs the reply whatever window it names; only the policy key's keyring signature binds it
    expect(verifies({ ...w.body, serverKeyringNotAfter: NOT_AFTER + 1 })).toBe(false);
    const { serverKeyringNotAfter: _window, ...dropped } = w.body;
    expect(verifies(dropped)).toBe(false);
    for (const bad of [1.5, -1, 2 ** 53, "x", null]) {
      expect(verifies({ ...w.body, serverKeyringNotAfter: bad } as unknown as Omit<SessionReply, "sig">), String(bad)).toBe(false);
    }
    expect(isAttestedSession(w.req, signSessionReply({ ...w.body, serverKeyringNotAfter: NOT_AFTER + 1 }, w.entry.privateKey), w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("anInheritedServerKeyringNotAfterNeverCounts", () => {
    const w = entryWorld();
    // the window dropped and the reply signed again by the entry key, so the reply's own signature holds and only
    // the keyring signature, read over own members, can refuse it
    const { serverKeyringNotAfter: _window, ...dropped } = w.body;
    const resigned = signSessionReply(dropped, w.entry.privateKey);
    const inheriting = Object.assign(Object.create({ serverKeyringNotAfter: NOT_AFTER }), resigned) as SessionReply;
    const { sig, ...signedBody } = inheriting;
    expect(verify(w.entry.publicKey, utf8("paztport-session-reply\n" + canonicalize(signedBody)), decode(sig))).toBe(true);
    expect(verifySessionReply(inheriting, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    // offline too, an inherited window does not select the keyring's signed bytes
    expect(isAttestedSession(w.req, inheriting, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("anOldFormEntryKeyReplyFailsLiveAndIsAcceptedOffline", () => {
    // only the server keyring is in the old form, so its form is the one reason the live check refuses
    const w = entryWorld({ oldFormKeyring: true });
    expect(Object.hasOwn(w.reply, "serverKeyringNotAfter")).toBe(false);
    expect(verifySessionReply(w.reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    const all = entryWorld({ oldForm: true });
    expect(verifySessionReply(all.reply, all.req, all.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
    expect(isAttestedSession(all.req, all.reply, all.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("anExpiredServerKeyringFailsLive", () => {
    const w = entryWorld({ keyringNotAfter: NOW });
    expect(verifySessionReply(w.reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(verifySessionReply(w.reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW + 1)).toBe(false);
    // offline the same window is judged at the record's time
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW + 1)).toBe(false);
  });
  it("anExpiredServerRootFailsLive", () => {
    const w = entryWorld();
    const root = signRoot(w.serverRootBytes, "v2", w.serverPolicy.privateKey, NOW);
    const body = { ...w.body, serverRoot: root, sess: deriveSessionId(w.clientRoot.sig, root.sig, w.req.nonce, w.body.nonce, w.req) };
    const reply = signSessionReply(body, w.entry.privateKey);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW + 1)).toBe(false);
  });
  it("anExpiredServerRootWithItsWindowExtendedFailsByTheRootsOwnSignature", () => {
    // the entry key signs the reply over the extended window, so the reply's signature holds; the root's does not
    const w = entryWorld();
    const expired = signRoot(w.serverRootBytes, "v2", w.serverPolicy.privateKey, NOW - 1);
    const extended: SignedRoot = { ...expired, notAfter: NOT_AFTER };
    const body = { ...w.body, serverRoot: extended, sess: deriveSessionId(w.clientRoot.sig, extended.sig, w.req.nonce, w.body.nonce, w.req) };
    const reply = signSessionReply(body, w.entry.privateKey);
    expect(verify(w.entry.publicKey, utf8("paztport-session-reply\n" + canonicalize(body)), decode(reply.sig))).toBe(true);
    expect(isCurrent(extended, NOW)).toBe(true);
    expect(verifyRoot(extended, w.serverPolicy.publicKey)).toBe(false);
    expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("theSameReplySignedByThePolicyKeyFails", () => {
    // the form is decided by the fields present, so the pin is never tried for an entry-key reply
    const w = entryWorld();
    expect(verifySessionReply(signSessionReply(w.body, w.serverPolicy.privateKey), w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("anEntryKeyReplyStrippedToTheOldFormFails", () => {
    const w = entryWorld();
    const { serverKeyringSig: _s, serverKeyringNotAfter: _w, serverReplyCert: _c, ...stripped } = w.body;
    expect(verifySessionReply(signSessionReply(stripped, w.entry.privateKey), w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("anotherConfiguredEntryFails", () => {
    const w = entryWorld();
    expect(verifySessionReply(w.reply, w.req, w.serverPolicy.publicKey, "github-tools", NOW)).toBe(false);
  });
  it("offlineOneSessionIsAttestedForCallsUpToNotAfterOnly", () => {
    const w = entryWorld();
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW + 1000)).toBe(true);
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW + 1001)).toBe(false);
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, Number.NaN)).toBe(false);
  });
  it("oldFormIgnoresTheTime", () => {
    // a policy-key reply over old-form material has no window anywhere: it is attested at any time
    const old = world(true);
    const reply = signSessionReply(old.body(), old.serverPolicy.privateKey);
    expect(isAttestedSession(old.req, reply, old.serverPolicy.publicKey, ENTRY, Number.MAX_SAFE_INTEGER)).toBe(true);
    // new-form material has windows, so the same reply form is attested only up to the earliest of them
    const w = world();
    const newReply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(w.req, newReply, w.serverPolicy.publicKey, ENTRY, NOT_AFTER)).toBe(true);
    expect(isAttestedSession(w.req, newReply, w.serverPolicy.publicKey, ENTRY, NOT_AFTER + 1)).toBe(false);
  });
  it("offlineJudgesEachNewFormWindowAtTheRecordsTime", () => {
    // one window at T, before the certificate's NOW + 1000 and the rest far off: the record at T counts, 1 ms after it
    // does not; each side's root and keyring
    const T = NOW + 500;
    const cases: [string, (w: ReturnType<typeof entryWorld>) => { req: SessionRequest; reply: SessionReply }][] = [
      ["client root", (w) => {
        const clientRoot = signRoot(w.clientRootBytes, "v1", w.clientPolicy.privateKey, T);
        const req = { ...w.req, clientRoot };
        const body = { ...w.body, sess: deriveSessionId(clientRoot.sig, w.serverRoot.sig, req.nonce, w.body.nonce, req) };
        return { req, reply: signSessionReply(body, w.entry.privateKey) };
      }],
      ["client keyring", (w) => {
        const ring = signKeyring(w.req.clientKeyring, w.clientPolicy.publicKey, w.clientPolicy.privateKey, T);
        return { req: { ...w.req, clientKeyringSig: ring.sig, clientKeyringNotAfter: T }, reply: w.reply };
      }],
      ["server root", (w) => {
        const serverRoot = signRoot(w.serverRootBytes, "v2", w.serverPolicy.privateKey, T);
        const body = { ...w.body, serverRoot, sess: deriveSessionId(w.clientRoot.sig, serverRoot.sig, w.req.nonce, w.body.nonce, w.req) };
        return { req: w.req, reply: signSessionReply(body, w.entry.privateKey) };
      }],
      ["server keyring", (w) => {
        const ring = signKeyring(w.body.serverKeyring, w.serverPolicy.publicKey, w.serverPolicy.privateKey, T);
        return { req: w.req, reply: signSessionReply({ ...w.body, serverKeyringSig: ring.sig, serverKeyringNotAfter: T }, w.entry.privateKey) };
      }],
    ];
    for (const [what, make] of cases) {
      const w = entryWorld();
      const { req, reply } = make(w);
      expect(isAttestedSession(req, reply, w.serverPolicy.publicKey, ENTRY, T), what).toBe(true);
      expect(isAttestedSession(req, reply, w.serverPolicy.publicKey, ENTRY, T + 1), what).toBe(false);
      expect(isAttestedSession(req, reply, w.serverPolicy.publicKey, ENTRY, Number.NaN), what).toBe(false);
    }
  });
  it("oldFormMaterialSetsNoLimitOffline", () => {
    // the certificate is the only window left: an old-form root or keyring, on either side, adds none
    const w = entryWorld({ oldForm: true });
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW + 1000)).toBe(true);
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW + 1001)).toBe(false);
    // an inherited window on old-form material is not a window either
    const inheriting = Object.assign(Object.create({ clientKeyringNotAfter: NOW }), w.req) as SessionRequest;
    expect(isAttestedSession(inheriting, w.reply, w.serverPolicy.publicKey, ENTRY, NOW + 1000)).toBe(true);
  });
  it("malformedNewFieldsFailWithoutThrowing", () => {
    const w = entryWorld();
    for (const bad of [{ serverKeyringSig: null }, { serverKeyringSig: 7 }, { serverReplyCert: null }, { serverReplyCert: { ...w.body.serverReplyCert, notAfter: 1.5 } }]) {
      const reply = signSessionReply({ ...w.body, ...bad } as unknown as Omit<SessionReply, "sig">, w.entry.privateKey);
      expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW), JSON.stringify(bad)).toBe(false);
    }
  });
});
