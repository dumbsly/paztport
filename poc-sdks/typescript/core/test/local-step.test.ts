// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned stamps: the pi extension's local gate signs these bytes for these inputs. Change only with a
// protocol change.

import { describe, expect, it } from "vitest";
import { encode } from "../src/b64url.ts";
import type { InfluenceEntry } from "../src/influence.ts";
import { localStepBind, stampLocalStep } from "../src/local-step.ts";

/** An Ed25519 PKCS#8 private key whose 32-byte seed is `b` repeated. */
const key = (b: number) => encode(Uint8Array.from([...Buffer.from("302e020100300506032b657004220420", "hex"), ...new Array<number>(32).fill(b)]));

const PI_KEY = key(2);
const RID = "cmlkLWZpeGVk";
const PREV = "4rqynmcDWi9lms_fN-r3djwt2OdO1h4PXpiJmxWOTQY50BktFK_avhJOGrehu5NrsgyteXaYQ1DSz6qVSAvaDA";
const HASH = "O4PSeU3uuGqyHLvGzHPsdxd4NO6wjDdX-J0A5UYU_7A";
const INFLUENCE: InfluenceEntry[] = [
  { cls: "private", src: "server:github", h: "h1" },
  { cls: "third-party", src: "server:github", h: "h1" },
];
const INFL = "K2uFRtqOJRvmqTeC77iMkgmlQbmzYb91qUyd8417TOI";
const step = { svc: "pi", inst: "pi-1", rid: RID, ts: 2000, prev: PREV, influence: INFLUENCE };

describe("stampLocalStep", () => {
  it("allowedReadMatchesTheGatesStamp", () => {
    const stamp = stampLocalStep(
      {
        ...step,
        toolName: "read",
        toolCallId: "call-1",
        input: { path: "<workspace>/website/README.md" },
        resolved: { paths: [{ need: "read", at: "website/README.md" }], programs: [], parse: "ok", readOnly: true },
        verdict: "OK",
        listed: true,
        rulesHash: HASH,
      },
      PI_KEY,
    );
    expect(stamp).toEqual({
      v: 2,
      svc: "pi",
      inst: "pi-1",
      rid: RID,
      ts: 2000,
      sess: "",
      bind: "jwh996pnIOX6duRgrsapCa2qnpdwrMiYVmW5VFxeEl4",
      infl: INFL,
      prev: PREV,
      sig: "pOxzfabNWnsunuylNWfzEEJI9zYCMjIIbn8l1SNHfaxsV0q7PZHRYKS8sZQSVg7QW00gFmVusbNeeI2z3LpBCQ",
    });
  });

  it("refusedWriteMatchesTheGatesStamp", () => {
    const stamp = stampLocalStep(
      {
        ...step,
        toolName: "write",
        toolCallId: "call-2",
        input: { path: "website/x.md", content: "hi" },
        resolved: { paths: [{ need: "write", at: "website/x.md" }], programs: [], parse: "ok", readOnly: false },
        verdict: "INFLUENCE_DENIED",
        listed: true,
        rulesHash: HASH,
      },
      PI_KEY,
    );
    expect(stamp.bind).toBe("AX64BK_1LR20VO6HXvhYKFeMGOxsdByR0Huo3FbQdHU");
    expect(stamp.sig).toBe("-Xee4X8KlDB8Wd4_fM8gDznnzNLlgC7hMSIHjy4NuU2vE1Cq-9-5iQU_GGkoMe14T_nHc-R45ksuBdbG7OkMBw");
  });

  it("unlistedWithNoRulesMatchesTheGatesStamp", () => {
    const stamp = stampLocalStep(
      {
        ...step,
        toolName: "ls",
        toolCallId: "call-3",
        input: { path: "." },
        resolved: { paths: [], programs: [], parse: "ok", readOnly: false },
        verdict: "SCOPE_DENIED",
        listed: false,
        rulesHash: null,
      },
      PI_KEY,
    );
    expect(stamp.bind).toBe("LF1MWJUcFAoGc5VzK3WV2TH8YL9XlOOo6MHe_mbN-8o");
    expect(stamp.sig).toBe("KoYUeePtTZuhLo7Vhc2_FpGRs_BTL7aA4iQLIyRIfW1sPEtkykIpN3UzvehH_YXRs_gr86s8yHsMXYF5Ux-SCg");
  });
});

describe("localStepBind", () => {
  it("isTheBindingTheGatesStampCarries", () => {
    const fields = {
      ...step,
      toolName: "read",
      toolCallId: "call-1",
      input: { path: "<workspace>/website/README.md" },
      resolved: { paths: [{ need: "read" as const, at: "website/README.md" }], programs: [], parse: "ok" as const, readOnly: true },
      verdict: "OK" as const,
      listed: true,
      rulesHash: HASH,
    };
    expect(localStepBind(fields)).toBe("jwh996pnIOX6duRgrsapCa2qnpdwrMiYVmW5VFxeEl4");
    expect(localStepBind(fields)).toBe(stampLocalStep(fields, PI_KEY).bind);
    // the call id and the decision are bound with the call
    expect(localStepBind({ ...fields, toolCallId: "call-2" })).not.toBe(localStepBind(fields));
    expect(localStepBind({ ...fields, listed: false })).not.toBe(localStepBind(fields));
    expect(localStepBind({ ...fields, rulesHash: null })).not.toBe(localStepBind(fields));
  });
});
