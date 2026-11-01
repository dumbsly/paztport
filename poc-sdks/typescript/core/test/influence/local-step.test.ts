// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned stamps: the pi extension's local gate signs these bytes for these inputs. Change only with a
// protocol change.

import { describe, expect, it } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import type { InfluenceEntry } from "../../src/influence/influence.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import {
  LOCAL_RECEIVER_PREFIX, localReceiver, localStepBind, readLocalDecision, stampLocalStep, type LocalDecision,
} from "../../src/influence/local-step.ts";

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
      v: 3,
      svc: "pi",
      inst: "pi-1",
      rid: RID,
      ts: 2000,
      sess: "",
      rcv: "local:read",
      bind: "jwh996pnIOX6duRgrsapCa2qnpdwrMiYVmW5VFxeEl4",
      infl: INFL,
      prev: PREV,
      sig: "2b4uZWSlZ1rvbDzKs26hSrUtxvSeTLos81L7aMm1gV1wXDf4L5YqFrkzJApn4xBjbPNmQ8PIRp9OMyMwmXeXCg",
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
    expect(stamp.rcv).toBe("local:write");
    expect(stamp.sig).toBe("3Tw536O9NfIPry6H54TzOYgJB9Ow6qndZuI4NuhI12aelrLO8CEtYI5zwUUw3j5GQ4wFMQw8aFJ39WeuHMJIDw");
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
    expect(stamp.rcv).toBe("local:ls");
    expect(stamp.sig).toBe("20J8BL7wEDyGAEyLzYXuGBGxgLGX1Ay7tIGiSRJzhoHgJ1kzlwaEbHCXkulW3bRE4QM8cX9tnqdMzpfw_hwLDw");
  });
});

describe("localReceiver", () => {
  it("namesTheToolAfterThePrefix", () => {
    expect(LOCAL_RECEIVER_PREFIX).toBe("local:");
    expect(localReceiver("read")).toBe("local:read");
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

describe("readLocalDecision", () => {
  const decision: LocalDecision = {
    callId: "tc-1",
    resolved: {
      paths: [{ need: "read", at: "notes.md" }], programs: [{ name: "git", via: "list" }], parse: "ok", readOnly: true,
    },
    verdict: "OK",
    routeAllowed: true,
    rulesHash: HASH,
  };
  /** The token of the decision with `edit` applied to a copy of its JSON. */
  const tokenWith = (edit: (d: any) => void): string => {
    const d = structuredClone(decision) as any;
    edit(d);
    return writeToken(d as JsonValue);
  };

  it("aDecisionReadsBackEqual", () => {
    expect(readLocalDecision(writeToken(decision as unknown as JsonValue))).toEqual(decision);
    const none = { ...decision, rulesHash: null };
    expect(readLocalDecision(writeToken(none as unknown as JsonValue))).toEqual(none);
  });

  it.each([
    ["an unknown verdict", (d: any) => { d.verdict = "MAYBE"; }, "verdict"],
    ["an unknown need", (d: any) => { d.resolved.paths[0].need = "delete"; }, "need"],
    ["an unknown via", (d: any) => { d.resolved.programs[0].via = "guess"; }, "via"],
    ["a parse other than ok or error", (d: any) => { d.resolved.parse = "maybe"; }, "parse"],
    ["a rulesHash that is neither a string nor null", (d: any) => { d.rulesHash = 7; }, "rulesHash"],
    ["a routeAllowed that is not a boolean", (d: any) => { d.routeAllowed = "yes"; }, "routeAllowed"],
    ["a readOnly that is not a boolean", (d: any) => { d.resolved.readOnly = 1; }, "readOnly"],
    ["an extra member in the decision", (d: any) => { d.extra = 1; }, "a member the object does not define"],
    ["an extra member in resolved", (d: any) => { d.resolved.extra = 1; }, "a member the object does not define"],
    [
      "an extra member in a path", (d: any) => { d.resolved.paths[0].extra = 1; },
      "a member the object does not define",
    ],
    [
      "an extra member in a program", (d: any) => { d.resolved.programs[0].extra = 1; },
      "a member the object does not define",
    ],
    ["a missing member", (d: any) => { delete d.rulesHash; }, "no member rulesHash"],
    ["a missing member in resolved", (d: any) => { delete d.resolved.readOnly; }, "no member readOnly"],
    ["a missing member in a path", (d: any) => { delete d.resolved.paths[0].at; }, "no member at"],
    ["a missing member in a program", (d: any) => { delete d.resolved.programs[0].via; }, "no member via"],
  ])("%s is refused", (_name, edit, message) => {
    expect(() => readLocalDecision(tokenWith(edit))).toThrow(message);
  });
});
