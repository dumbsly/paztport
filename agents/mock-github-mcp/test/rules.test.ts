// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { InfluenceClass, InfluenceEntry } from "@paztport/path-attest";
import { GITHUB_TOOLS, type GithubTool } from "../src/github.ts";
import { influenceDecision } from "../src/rules.ts";

const tool = (name: string): GithubTool => GITHUB_TOOLS.find((t) => t.name === name)!;
const infl = (...classes: InfluenceClass[]): InfluenceEntry[] => classes.map((cls, i) => ({ cls, src: `src-${i}`, h: `h-${i}` }));
const WRITES = GITHUB_TOOLS.filter((t) => t.kind === "write");
const READS = GITHUB_TOOLS.filter((t) => t.kind === "read");

describe("influenceDecision", () => {
  it("publicWriteWithThirdPartyAndPrivateDenied", () => {
    expect(WRITES).toHaveLength(5);
    for (const t of WRITES) {
      expect(influenceDecision(t, true, infl("third-party", "private"))).toBe("INFLUENCE_DENIED");
      expect(influenceDecision(t, true, infl("public", "private", "public", "third-party"))).toBe("INFLUENCE_DENIED");
    }
  });
  it("localUntrustedCountsAsThirdParty", () => {
    for (const t of WRITES) {
      expect(influenceDecision(t, true, infl("local-untrusted", "private"))).toBe("INFLUENCE_DENIED");
    }
  });
  it("publicWriteThirdPartyOnlyAllowed", () => {
    // the legitimate typo fix: the issue (third-party) plus public repo reads
    for (const t of WRITES) {
      expect(influenceDecision(t, true, infl("third-party"))).toBe("OK");
      expect(influenceDecision(t, true, infl("third-party", "public", "local-untrusted"))).toBe("OK");
      expect(influenceDecision(t, true, infl("private", "public"))).toBe("OK");
      expect(influenceDecision(t, true, [])).toBe("OK");
    }
  });
  it("privateDestinationAllowed", () => {
    for (const t of WRITES) {
      expect(influenceDecision(t, false, infl("third-party", "private", "local-untrusted"))).toBe("OK");
    }
  });
  it("readsAlwaysAllowed", () => {
    expect(READS).toHaveLength(4);
    for (const t of READS) {
      expect(influenceDecision(t, true, infl("third-party", "private", "local-untrusted"))).toBe("OK");
      expect(influenceDecision(t, false, infl("third-party", "private"))).toBe("OK");
    }
    expect(influenceDecision(tool("get_file_contents"), true, infl("private", "third-party"))).toBe("OK");
  });
});
