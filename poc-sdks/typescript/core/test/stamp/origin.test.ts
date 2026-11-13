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
import { commitBlock, EMPTY_BLOCK, makeBlock } from "../../src/stamp/block.ts";
import { mintOrigin } from "../../src/stamp/origin.ts";
import { signStamp } from "../../src/stamp/stamp.ts";
import { NO_EXTENSIONS } from "../../src/verify/extensions.ts";
import { verifyChain } from "../../src/verify/verify-chain.ts";

/** An Ed25519 PKCS#8 private key whose 32-byte seed is `b` repeated. */
const key = (b: number) => encode(Uint8Array.from([...Buffer.from("302e020100300506032b657004220420", "hex"), ...new Array<number>(32).fill(b)]));

const SESSION_KEY = key(1);
const RID = "cmlkLWZpeGVk";
const SESS = "c2Vzcy1maXhlZA";
const BIND = "lTDYRIdSYWE9xSD3h0zanGdyXnUEr9sgF_SKBkk_J1Y";
const F = { svc: "session", rid: RID, ts: 1000, bind: BIND, sess: SESS, inst: "pi-1", rcv: "pi", block: EMPTY_BLOCK };

describe("mintOrigin", () => {
  it("matchesTheRunStatesStamp", () => {
    expect(bindPrompt("Fix the README typo")).toBe(BIND);
    expect(mintOrigin(F, SESSION_KEY)).toEqual({
      v: 4,
      svc: "session",
      inst: "pi-1",
      rid: RID,
      ts: 1000,
      sess: SESS,
      rcv: "pi",
      bind: BIND,
      ext: "",
      prev: "",
      sig: "_RAnSM7Abwv23Ii8JtV_9pWCrcyFV8hqfS3rj2ag1IadhQTWss8unE4b5e86NGrtQiSLHs2tUMypsqB-_eBcBQ",
    });
  });

  it("signsAsTheServiceItIsGiven", () => {
    const origin = mintOrigin({ ...F, svc: "run-origin" }, SESSION_KEY);
    expect(origin.svc).toBe("run-origin");
    expect(origin.sig).not.toBe(mintOrigin(F, SESSION_KEY).sig);
  });

  it("commitsToTheBlockItIsGiven", () => {
    expect(mintOrigin(F, SESSION_KEY).ext).toBe("");
    const block = makeBlock({ example: [] }, ["example"]);
    const origin = mintOrigin({ ...F, block }, SESSION_KEY);
    expect(origin.ext).toBe(commitBlock(block));
    expect(origin.ext).not.toBe("");
  });

  it("verifiesAsTheFirstStampOfAChain", () => {
    const session = generateKeyPair();
    const pi = generateKeyPair();
    const receiver = "mcp:github.t";
    const tree = buildTree([`session/pi/${receiver}`].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
    const origin = mintOrigin(F, session.privateKey);
    expect(origin).toMatchObject({ v: 4, rcv: "pi" });
    const hop = signStamp({ svc: "pi", inst: "pi-1", rid: RID, ts: 1000, sess: SESS, rcv: receiver, bind: "b1", ext: "", prev: origin.sig }, pi.privateKey);
    const r = verifyChain(
      {
        chain: writeToken([origin, hop]), expectedBind: "b1", blocks: null,
        proof: writeToken(tree.proofFor(`session/pi/${receiver}`)), receiver, receiverInRoute: true,
      },
      {
        keyrings: [{ keys: { session: session.publicKey, pi: pi.publicKey }, notAfter: 4_102_444_800_000 }],
        roots: [{ root: tree.root, rootId: tree.rootId, notAfter: 4_102_444_800_000 }],
        allowedOrigins: ["session"],
        sess: SESS,
        nonces: new NonceCache(60_000),
        nonceKey: "k",
        now: 1000,
        policyNotAfter: 4_102_444_800_000,
        extensions: NO_EXTENSIONS,
      },
    );
    expect(r.reason).toBe("OK");
  });

  it("signsAPipeInAFieldButNotInARouteNode", () => {
    expect(mintOrigin({ ...F, sess: "a|b" }, SESSION_KEY).sess).toBe("a|b");
    expect(() => mintOrigin({ ...F, rcv: "p|i" }, SESSION_KEY)).toThrow(/^rcv must be a route node/);
  });
});
