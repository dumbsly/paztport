// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned stamp: the pi extension's run state signed these bytes for these inputs before minting moved
// to core. Change only with a protocol change.

import { describe, expect, it } from "vitest";
import { encode } from "../src/b64url.ts";
import { bindPrompt } from "../src/binding.ts";
import { mintOrigin } from "../src/origin.ts";

/** An Ed25519 PKCS#8 private key whose 32-byte seed is `b` repeated. */
const key = (b: number) => encode(Uint8Array.from([...Buffer.from("302e020100300506032b657004220420", "hex"), ...new Array<number>(32).fill(b)]));

const SESSION_KEY = key(1);
const RID = "cmlkLWZpeGVk";
const SESS = "c2Vzcy1maXhlZA";
const BIND = "lTDYRIdSYWE9xSD3h0zanGdyXnUEr9sgF_SKBkk_J1Y";

describe("mintOrigin", () => {
  it("matchesTheRunStatesStamp", () => {
    expect(bindPrompt("Fix the README typo")).toBe(BIND);
    expect(mintOrigin({ rid: RID, ts: 1000, bind: BIND, sess: SESS, inst: "pi-1" }, SESSION_KEY)).toEqual({
      v: 2,
      svc: "session",
      inst: "pi-1",
      rid: RID,
      ts: 1000,
      sess: SESS,
      bind: BIND,
      infl: "",
      prev: "",
      sig: "ETYJD0-rMGcecCIL-zijDWoyoo5zO5l8powx2aKjYTrRhao0xTE_IOAFWJQS6z_YvS2RtuCs8j-KZXOlh-fbCg",
    });
  });

  it("refusesADelimiterInAField", () => {
    expect(() => mintOrigin({ rid: RID, ts: 1000, bind: BIND, sess: "a|b", inst: "pi-1" }, SESSION_KEY)).toThrow("'|'");
  });
});
