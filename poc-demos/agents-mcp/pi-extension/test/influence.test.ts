// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindResult } from "@paztport/core";
import { InfluenceStore, contentHash } from "../src/influence.ts";

describe("InfluenceStore", () => {
  it("labelsBecomeEntriesWithCid", () => {
    const s = new InfluenceStore();
    s.recordLabels("github", [{ cls: "third-party", cid: "c1" }, { cls: "private", cid: "c2" }], "H1");
    expect(s.entries()).toEqual(
      expect.arrayContaining([
        { cls: "third-party", src: "server:github", h: "H1", cid: "c1" },
        { cls: "private", src: "server:github", h: "H1", cid: "c2" },
      ]),
    );
    expect(s.entries()).toHaveLength(2);
    expect(s.classes()).toEqual(new Set(["third-party", "private"]));
  });

  it("untrustedEntry", () => {
    const s = new InfluenceStore();
    s.recordUntrusted("server:evil", "H2");
    expect(s.entries()).toEqual([{ cls: "local-untrusted", src: "server:evil", h: "H2" }]);
    expect(s.entries()[0]).not.toHaveProperty("cid");
    expect(s.classes()).toEqual(new Set(["local-untrusted"]));
  });

  it("unknownEntryIsPrivateAndUntrusted", () => {
    const s = new InfluenceStore();
    s.recordUnknown("local:branch_summary", "H4");
    expect(s.entries()).toEqual([
      { cls: "local-untrusted", src: "local:branch_summary", h: "H4" },
      { cls: "private", src: "local:branch_summary", h: "H4" },
    ]);
  });

  it("classesBecomeEntriesWithoutCid", () => {
    // rebuilt from a restored session branch, which keeps label classes but no cids
    const s = new InfluenceStore();
    s.recordClasses("github", ["third-party", "private"], "H3");
    expect(s.entries()).toEqual([
      { cls: "private", src: "server:github", h: "H3" },
      { cls: "third-party", src: "server:github", h: "H3" },
    ]);
    expect(s.classes()).toEqual(new Set(["third-party", "private"]));
  });

  it("entriesNormalisedAndDeduped", () => {
    const s = new InfluenceStore();
    s.recordUntrusted("b", "Z");
    s.recordUntrusted("a", "A");
    s.recordUntrusted("a", "A");
    s.recordLabels("s", [{ cls: "public", cid: "c" }], "M");
    s.recordLabels("s", [{ cls: "public", cid: "c" }], "M");
    const e = s.entries();
    expect(e).toHaveLength(3);
    expect(e.map((x) => x.h)).toEqual(["A", "M", "Z"]);
  });

  it("a label's owner becomes the entry's owner", () => {
    const s = new InfluenceStore();
    s.recordLabels("github", [{ cls: "private", cid: "c", owner: "alice" }], "h");
    expect(s.entries()).toEqual([{ cls: "private", src: "server:github", h: "h", cid: "c", owner: "alice" }]);
  });

  it("summaryHasNoHashes", () => {
    const s = new InfluenceStore();
    s.recordLabels("github", [{ cls: "third-party", cid: "CID-SECRET" }], "HASH-SECRET");
    s.recordUntrusted("SRC-SECRET", "HASH2");
    s.recordUntrusted("SRC-SECRET2", "HASH3");
    const sum = s.summary();
    expect(sum).toEqual({ "third-party": 1, private: 0, public: 0, "local-untrusted": 2 });
    const json = JSON.stringify(sum);
    for (const secret of ["CID-SECRET", "HASH-SECRET", "SRC-SECRET", "HASH2", "github"]) {
      expect(json).not.toContain(secret);
    }
    expect(Object.values(sum).every((n) => typeof n === "number")).toBe(true);
  });

  it("resetClears", () => {
    const s = new InfluenceStore();
    s.recordUntrusted("a", "A");
    s.reset();
    expect(s.entries()).toEqual([]);
    expect(s.classes().size).toBe(0);
    expect(s.summary()).toEqual({ "third-party": 0, private: 0, public: 0, "local-untrusted": 0 });
  });

  it("entriesReturnsACopy", () => {
    const s = new InfluenceStore();
    s.recordUntrusted("a", "A");
    s.entries().pop();
    expect(s.entries()).toHaveLength(1);
  });
});

describe("contentHash", () => {
  it("contentHashIgnoresMeta", () => {
    const r = { content: [{ type: "text", text: "hi" }], isError: false };
    const withMeta = { ...r, _meta: { "paztport/attestation": { x: 1 } } };
    expect(contentHash(withMeta)).toBe(contentHash(r));
    expect(contentHash({ ...r, content: [{ type: "text", text: "ho" }] })).not.toBe(contentHash(r));
    // The content hash is the library's domain-separated result binding.
    expect(contentHash(r)).toBe(bindResult(r));
    expect(contentHash(withMeta)).toBe(bindResult(withMeta));
  });
});
