// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../src/b64url.ts";
import { generateKeyPair, randomBytes, sign, utf8, verify } from "../src/crypto.ts";
import { canonicalize } from "../src/jcs.ts";
import { signKeyring, signKeyringOldForm } from "../src/keyring.ts";
import { issueReplyCert } from "../src/reply-cert.ts";
import { signRoot, signRootOldForm } from "../src/root.ts";
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
  const root = (id: string, key: string) => (oldForm ? signRootOldForm(randomBytes(32), id, key) : signRoot(randomBytes(32), id, key, NOT_AFTER));
  const clientRoot = root("v1", clientPolicy.privateKey);
  const serverRoot = root("v2", serverPolicy.privateKey);
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
  return { clientPolicy, serverPolicy, clientRoot, serverRoot, req, body, pinned };
}

describe("sessionStatus", () => {
  it("bothRootsAttested", () => {
    const w = world();
    expect(sessionStatus(w.req, w.serverRoot, w.serverPolicy.publicKey, w.pinned)).toBe("attested");
  });
  it("missingClientRootUnsafe", () => {
    const w = world();
    expect(sessionStatus({ ...w.req, clientRoot: null }, w.serverRoot, w.serverPolicy.publicKey, w.pinned)).toBe("unsafe");
  });
  it("clientRootBadSigUnsafe", () => {
    const w = world();
    const bad = { ...w.clientRoot, sig: encode(randomBytes(64)) };
    expect(sessionStatus({ ...w.req, clientRoot: bad }, w.serverRoot, w.serverPolicy.publicKey, w.pinned)).toBe("unsafe");
  });
  it("missingServerRootUnsafe", () => {
    const w = world();
    expect(sessionStatus(w.req, null, w.serverPolicy.publicKey, w.pinned)).toBe("unsafe");
  });
  it("aClientPolicyKeyThatIsNotPinnedIsUnsafe", () => {
    const w = world();
    expect(sessionStatus(w.req, w.serverRoot, w.serverPolicy.publicKey, [generateKeyPair().publicKey])).toBe("unsafe");
  });
  it("noPinnedClientKeysIsUnsafe", () => {
    const w = world();
    expect(sessionStatus(w.req, w.serverRoot, w.serverPolicy.publicKey, [])).toBe("unsafe");
  });
  it("aKeyringAlteredSinceSigningIsUnsafe", () => {
    const w = world();
    expect(sessionStatus({ ...w.req, clientKeyring: { session: "evil" } }, w.serverRoot, w.serverPolicy.publicKey, w.pinned)).toBe("unsafe");
  });
  it("anEmptyPinNeverMatches", () => {
    const w = world();
    expect(sessionStatus(w.req, w.serverRoot, w.serverPolicy.publicKey, [""])).toBe("unsafe");
    expect(sessionStatus({ ...w.req, clientPolicyKey: "" }, w.serverRoot, w.serverPolicy.publicKey, [""])).toBe("unsafe");
  });
  it("anEmptyKeyringSignatureIsUnsafe", () => {
    const w = world();
    expect(sessionStatus({ ...w.req, clientKeyringSig: "" }, w.serverRoot, w.serverPolicy.publicKey, w.pinned)).toBe("unsafe");
  });
  it("clientKeyringNotAfterIsCoveredByTheKeyringSignature", () => {
    const w = world();
    const status = (req: SessionRequest) => sessionStatus(req, w.serverRoot, w.serverPolicy.publicKey, w.pinned);
    expect(w.req.clientKeyringNotAfter).toBe(NOT_AFTER);
    expect(status(w.req)).toBe("attested");
    // moved or dropped in transit, the keyring signature fails in the form the request now claims
    expect(status({ ...w.req, clientKeyringNotAfter: NOT_AFTER + 1 })).toBe("unsafe");
    const { clientKeyringNotAfter: _window, ...dropped } = w.req;
    expect(status(dropped)).toBe("unsafe");
    // a present value that is not an integer in range never reads as the old form
    for (const bad of [1.5, -1, 2 ** 53, "x", null, true, {}, []]) {
      expect(status({ ...w.req, clientKeyringNotAfter: bad } as unknown as SessionRequest), String(bad)).toBe("unsafe");
    }
  });
  it("anInheritedClientKeyringNotAfterNeverCounts", () => {
    const w = world();
    const { clientKeyringNotAfter: _window, ...dropped } = w.req;
    const inheriting = (req: object) => Object.assign(Object.create({ clientKeyringNotAfter: NOT_AFTER }), req) as SessionRequest;
    expect(sessionStatus(inheriting(dropped), w.serverRoot, w.serverPolicy.publicKey, w.pinned)).toBe("unsafe");
    // an old-form keyring is checked in the old form, whatever its prototype offers
    const old = world(true);
    expect(sessionStatus(inheriting(old.req), old.serverRoot, old.serverPolicy.publicKey, old.pinned)).toBe("attested");
  });
  it("oldFormMaterialIsStillAttested", () => {
    // nothing is refused for being in the old form yet
    const w = world(true);
    expect(Object.hasOwn(w.req, "clientKeyringNotAfter")).toBe(false);
    expect(sessionStatus(w.req, w.serverRoot, w.serverPolicy.publicKey, w.pinned)).toBe("attested");
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
    const w = world(true);
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(w.req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
  });
  it("aLegacyRequestWithAnAttestedReplyIsAttested", () => {
    const w = world();
    const { clientKeyringSig: _sig, ...legacy } = w.req;
    const req: LegacySessionRequest = legacy;
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(req, reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
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
   * A reply signed by mcp-entry's key, with the server keyring's signature and window and a certificate valid until
   * NOW + 1000; `oldForm` signs the keyring in the old form, with no `serverKeyringNotAfter`.
   */
  function entryWorld(oldForm = false) {
    const w = world(oldForm);
    const entry = generateKeyPair();
    const services = { "mcp-entry": entry.publicKey, "github-tools": generateKeyPair().publicKey };
    const ring = oldForm
      ? signKeyringOldForm(services, w.serverPolicy.publicKey, w.serverPolicy.privateKey)
      : signKeyring(services, w.serverPolicy.publicKey, w.serverPolicy.privateKey, NOT_AFTER);
    const cert = issueReplyCert(w.serverPolicy.publicKey, ENTRY, entry.publicKey, NOW + 1000, w.serverPolicy.privateKey);
    const body: Omit<SessionReply, "sig"> = {
      ...w.body(), serverKeyring: services, serverKeyringSig: ring.sig, ...(oldForm ? {} : { serverKeyringNotAfter: NOT_AFTER }), serverReplyCert: cert,
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
    const { serverKeyringNotAfter: _window, ...dropped } = w.reply;
    const inheriting = Object.assign(Object.create({ serverKeyringNotAfter: NOT_AFTER }), dropped) as SessionReply;
    expect(verifySessionReply(inheriting, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(false);
  });
  it("anOldFormEntryKeyReplyStillVerifies", () => {
    const w = entryWorld(true);
    expect(Object.hasOwn(w.reply, "serverKeyringNotAfter")).toBe(false);
    expect(verifySessionReply(w.reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
    expect(isAttestedSession(w.req, w.reply, w.serverPolicy.publicKey, ENTRY, NOW)).toBe(true);
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
    const w = world();
    const reply = signSessionReply(w.body(), w.serverPolicy.privateKey);
    expect(isAttestedSession(w.req, reply, w.serverPolicy.publicKey, ENTRY, Number.MAX_SAFE_INTEGER)).toBe(true);
  });
  it("malformedNewFieldsFailWithoutThrowing", () => {
    const w = entryWorld();
    for (const bad of [{ serverKeyringSig: null }, { serverKeyringSig: 7 }, { serverReplyCert: null }, { serverReplyCert: { ...w.body.serverReplyCert, notAfter: 1.5 } }]) {
      const reply = signSessionReply({ ...w.body, ...bad } as unknown as Omit<SessionReply, "sig">, w.entry.privateKey);
      expect(verifySessionReply(reply, w.req, w.serverPolicy.publicKey, ENTRY, NOW), JSON.stringify(bad)).toBe(false);
    }
  });
});
