// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { labelFor } from "../src/labels.ts";
import type { ToolOutcome } from "../src/github.ts";

const read = (what: "issues" | "file" | "repo-list", includesPrivate: boolean): ToolOutcome => ({
  text: "x",
  read: { owner: "acme", repo: "r", what, includesPrivate },
});

describe("labelFor", () => {
  it("issuesAreThirdParty", () => {
    expect(labelFor(read("issues", false))).toBe("third-party");
    expect(labelFor(read("issues", true))).toBe("third-party");
  });
  it("privateFileIsPrivate", () => {
    expect(labelFor(read("file", true))).toBe("private");
  });
  it("publicFileIsPublic", () => {
    expect(labelFor(read("file", false))).toBe("public");
  });
  it("repoListWithPrivateIsPrivate", () => {
    expect(labelFor(read("repo-list", true))).toBe("private");
    expect(labelFor(read("repo-list", false))).toBe("public");
  });
  it("writesArePublic", () => {
    expect(labelFor({ text: "w", write: { owner: "acme", repo: "r", texts: ["a"] } })).toBe("public");
    expect(labelFor({ text: "e", isError: true })).toBe("public");
  });
});
