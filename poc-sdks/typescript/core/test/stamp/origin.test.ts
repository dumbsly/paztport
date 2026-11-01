// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned stamp: the pi extension's run state signs these bytes for these inputs. Change only with a
// protocol change.

import { describe, expect, it } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import { bindPrompt } from "../../src/stamp/binding.ts";
import { generateKeyPair, randomBytes } from "../../src/crypto/crypto.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { NonceCache } from "../../src/verify/nonce.ts";
import { mintOrigin } from "../../src/stamp/origin.ts";
import { signStampV3 } from "../../src/stamp/stamp.ts";
import { verifyChainV3 } from "../../src/verify/verify-v3.ts";

/** An Ed25519 PKCS#8 private key whose 32-byte seed is `b` repeated. */
const key = (b: number) => encode(Uint8Array.from([...Buffer.from("302e020100300506032b657004220420", "hex"), ...new Array<number>(32).fill(b)]));

const SESSION_KEY = key(1);
const RID = "cmlkLWZpeGVk";
const SESS = "c2Vzcy1maXhlZA";
const BIND = "lTDYRIdSYWE9xSD3h0zanGdyXnUEr9sgF_SKBkk_J1Y";

describe("mintOrigin", () => {
  it("matchesTheRunStatesStamp", () => {
    expect(bindPrompt("Fix the README typo")).toBe(BIND);
    expect(mintOrigin({ svc: "session", rid: RID, ts: 1000, bind: BIND, sess: SESS, inst: "pi-1", rcv: "pi" }, SESSION_KEY)).toEqual({
      v: 3,
      svc: "session",
      inst: "pi-1",
      rid: RID,
      ts: 1000,
      sess: SESS,
      rcv: "pi",
      bind: BIND,
      infl: "",
      prev: "",
      sig: "Xnqi9XsWMZNlegIbRLDxvqTwBJ3PO0B5zOkYwM5zCH8cmW0bwjr2ols66Uj6L6tHcresr5ofQYmbrS7xhnF-AA",
    });
  });

  it("signsAsTheServiceItIsGiven", () => {
    const origin = mintOrigin({ svc: "run-origin", rid: RID, ts: 1000, bind: BIND, sess: SESS, inst: "pi-1", rcv: "pi" }, SESSION_KEY);
    expect(origin.svc).toBe("run-origin");
    expect(origin.sig).not.toBe(mintOrigin({ svc: "session", rid: RID, ts: 1000, bind: BIND, sess: SESS, inst: "pi-1", rcv: "pi" }, SESSION_KEY).sig);
  });

  it("verifiesAsTheFirstStampOfAV3Chain", () => {
    const session = generateKeyPair();
    const pi = generateKeyPair();
    const receiver = "mcp:github.t";
    const tree = buildTree([`session/pi/${receiver}`].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
    const origin = mintOrigin({ svc: "session", rid: RID, ts: 1000, bind: BIND, sess: SESS, inst: "pi-1", rcv: "pi" }, session.privateKey);
    expect(origin).toMatchObject({ v: 3, rcv: "pi" });
    const hop = signStampV3({ svc: "pi", inst: "pi-1", rid: RID, ts: 1000, sess: SESS, rcv: receiver, bind: "b1", infl: "", prev: origin.sig }, pi.privateKey);
    const r = verifyChainV3(
      {
        chain: writeToken([origin, hop]), expectedBind: "b1", influence: writeToken([]),
        proof: writeToken(tree.proofFor(`session/pi/${receiver}`)), receiver, receiverInRoute: true,
      },
      {
        keyring: { session: session.publicKey, pi: pi.publicKey },
        root: tree.root,
        rootId: tree.rootId,
        allowedOrigins: ["session"],
        sess: SESS,
        nonces: new NonceCache(60_000),
        nonceKey: "k",
        now: 1000,
        policyNotAfter: 4_102_444_800_000,
      },
    );
    expect(r.reason).toBe("OK");
  });

  it("refusesADelimiterInAField", () => {
    expect(() => mintOrigin({ svc: "session", rid: RID, ts: 1000, bind: BIND, sess: "a|b", inst: "pi-1", rcv: "pi" }, SESSION_KEY)).toThrow("'|'");
    expect(() => mintOrigin({ svc: "session", rid: RID, ts: 1000, bind: BIND, sess: SESS, inst: "pi-1", rcv: "p|i" }, SESSION_KEY)).toThrow("'|'");
  });
});
