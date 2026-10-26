// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindPrompt, decode, generateKeyPair, signingBytesV2, verify } from "@paztport/core";
import { RunState } from "../src/runs.ts";

const key = generateKeyPair();

describe("RunState", () => {
  it("startMintsFreshRid", () => {
    const r = new RunState();
    expect(r.current()).toBeUndefined();
    r.start("hello", 1000);
    const a = r.current()!;
    r.start("hello", 1000);
    const b = r.current()!;
    expect(a.rid).not.toBe(b.rid);
    expect(decode(a.rid)).toHaveLength(16);
    expect(a).toEqual({ rid: a.rid, ts: 1000, bind: bindPrompt("hello") });
  });

  it("originCachedPerRidAndSess", () => {
    const r = new RunState();
    r.start("p", 5);
    const a = r.origin("S1", key.privateKey, "inst");
    const b = r.origin("S1", key.privateKey, "inst");
    expect(b).toBe(a);
  });

  it("originDiffersPerSess", () => {
    const r = new RunState();
    r.start("p", 5);
    const a = r.origin("S1", key.privateKey, "inst");
    const b = r.origin("S2", key.privateKey, "inst");
    expect(a.sess).toBe("S1");
    expect(b.sess).toBe("S2");
    expect(a.sig).not.toBe(b.sig);
    expect(a.rid).toBe(b.rid);
  });

  it("newRunNewOrigin", () => {
    const r = new RunState();
    r.start("p", 5);
    const a = r.origin("S1", key.privateKey, "inst");
    r.start("p", 5);
    const b = r.origin("S1", key.privateKey, "inst");
    expect(b).not.toBe(a);
    expect(b.rid).not.toBe(a.rid);
    expect(b.sig).not.toBe(a.sig);
  });

  it("noRunRefusesLocally", () => {
    const r = new RunState();
    expect(() => r.origin("S1", key.privateKey, "inst")).toThrow("no active run");
  });

  it("originUsesRunTimestampAndPromptBind", () => {
    const r = new RunState();
    r.start("the prompt", 4242);
    const o = r.origin("S9", key.privateKey, "my-inst");
    const { sig, ...rest } = o;
    expect(rest).toEqual({
      v: 2,
      svc: "session",
      inst: "my-inst",
      rid: r.current()!.rid,
      ts: 4242,
      sess: "S9",
      bind: bindPrompt("the prompt"),
      infl: "",
      prev: "",
    });
    expect(verify(key.publicKey, signingBytesV2(rest), decode(sig))).toBe(true);
  });
});
