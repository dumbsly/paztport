// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned bytes for cross-implementation conformance (plan 1b and any future v2 implementation
// must reproduce these). Change only with a protocol change.

import { describe, expect, it } from "vitest";
import {
  bindMcpCall, bindPrompt, bindResponse, bindResult, commitInfluence, deriveSessionId, encode, signingBytesV2,
} from "../src/index.ts";

/** n consecutive bytes starting at `start`, base64url. */
const seq = (start: number, n: number) => encode(Uint8Array.from({ length: n }, (_, i) => start + i));

const CLIENT_ROOT_SIG = seq(0x01, 64); // 0x01..0x40
const SERVER_ROOT_SIG = seq(0x41, 64); // 0x41..0x80
const CLIENT_NONCE = seq(0xa0, 16); // 0xa0..0xaf
const SERVER_NONCE = seq(0xb0, 16); // 0xb0..0xbf
const CLIENT_KEYS = { clientPolicyKey: "client-policy-key", clientKeyring: { session: "harness-key", pi: "harness-key" } };

describe("v2 known-answer vectors", () => {
  it("fixed inputs encode as expected", () => {
    expect(CLIENT_ROOT_SIG).toBe("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QA");
    expect(SERVER_ROOT_SIG).toBe("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gA");
    expect(CLIENT_NONCE).toBe("oKGio6SlpqeoqaqrrK2urw");
    expect(SERVER_NONCE).toBe("sLGys7S1tre4ubq7vL2-vw");
  });

  it.each([
    ["both roots", CLIENT_ROOT_SIG, SERVER_ROOT_SIG, "Sihmp4JNFGGxfYjPSXSMuSUaOfj3STn55ToB7yOcRp0"],
    ["client root null", null, SERVER_ROOT_SIG, "dAK3HV9_ZQOkDJNgtMYlPBwcVAa33Hza3QV_qV4GvrY"],
    ["server root null", CLIENT_ROOT_SIG, null, "_WFC-8gbHWAqLj7pCSHLa-gIlW2TVSa0RMpjgUpj3Ws"],
  ])("deriveSessionId: %s", (_name, clientSig, serverSig, expected) => {
    expect(deriveSessionId(clientSig, serverSig, CLIENT_NONCE, SERVER_NONCE, CLIENT_KEYS)).toBe(expected);
  });

  it("bindResponse", () => {
    const labels = [{ cls: "third-party" as const, cid: "cid-1" }, { cls: "private" as const, cid: "cid-2" }];
    expect(bindResponse("result-hash", "call-1", labels)).toBe("8uSt7UKQxhX_wUTDkOHv-CWfU6QeBCJN9Gkb1K_WsNM");
  });

  it("bindMcpCall", () => {
    const args = { title: "t", body: "b", draft: false, n: [1, 2.5] };
    expect(bindMcpCall("create_pull_request", "call-1", args)).toBe("1dK9R69lTXmP45Z9HIVEmO9EtY_bRq68vJvEO_tdZv8");
  });

  it("bindPrompt", () => {
    expect(bindPrompt("open a PR for issue #42")).toBe("GHG2oeO8ahTQudo8ccWAGXTPNXpDcXX_dY_l1pjy4Uk");
  });

  it("bindResult", () => {
    const result = { content: [{ type: "text", text: "hi" }], isError: false, _meta: { x: 1 } };
    expect(bindResult(result)).toBe("YBkqnV0tWMJE84KUs7n6DNLf75P0zwF096oAvlJ2Zxw");
  });

  it("commitInfluence", () => {
    const entries = [
      { cls: "third-party" as const, src: "web:example.com", h: "h2" },
      { cls: "private" as const, src: "file:notes.md", h: "h1", cid: "cid-1" },
      { cls: "public" as const, src: "web:docs.example.org", h: "h3" },
    ];
    expect(commitInfluence(entries)).toBe("1tNgtedjp7S6FojkCifg0XASNGvw8mxK2QiYPVfCyDw");
  });

  it("signingBytesV2", () => {
    const stamp = {
      v: 2 as const, svc: "pi", inst: "pi-1", rid: "rid-1", ts: 1767225600000,
      sess: "sess-1", bind: "bind-1", infl: "infl-1", prev: "prev-1",
    };
    expect(Buffer.from(signingBytesV2(stamp)).toString("hex")).toBe(
      "327c70697c70692d317c7269642d317c313736373232353630303030307c736573732d317c62696e642d317c696e666c2d317c707265762d31",
    );
  });
});
