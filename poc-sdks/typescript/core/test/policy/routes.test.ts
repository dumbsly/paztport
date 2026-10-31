// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { requireValidNode, routeOf, rulesRoute, rulesRouteNodes } from "../../src/policy/routes.ts";

describe("routes", () => {
  it("joinsOneTwoAndThreeHopRoutesWithSlashes", () => {
    expect(routeOf(["gateway"])).toBe("gateway");
    expect(routeOf(["gateway", "orders"])).toBe("gateway/orders");
    expect(routeOf(["gateway", "orders", "payment"])).toBe("gateway/orders/payment");
  });

  it("rulesRouteIsTheClientChainThenRulesHash", () => {
    expect(rulesRouteNodes(["session", "pi"], "abc")).toEqual(["session", "pi", "rules:abc"]);
    expect(rulesRoute(["session", "pi"], "abc")).toBe("session/pi/rules:abc");
    expect(rulesRoute(["a"], "h")).toBe("a/rules:h");
  });

  it("rulesRouteNodesLeavesTheChainUntouched", () => {
    const chain = ["session", "pi"];
    rulesRouteNodes(chain, "abc");
    expect(chain).toEqual(["session", "pi"]);
  });

  it("refusesAnEmptyNode", () => {
    expect(() => requireValidNode("")).toThrow("route node must not be empty");
  });

  it("refusesTheDotNodes", () => {
    expect(() => requireValidNode(".")).toThrow('route node must not be "."');
    expect(() => requireValidNode("..")).toThrow('route node must not be ".."');
  });

  it("refusesASlash", () => {
    expect(() => requireValidNode("a/b")).toThrow(`route node "a/b" must not contain '/'`);
    expect(() => requireValidNode("/")).toThrow(`must not contain '/'`);
  });

  it("refusesABackslash", () => {
    expect(() => requireValidNode("a\\b")).toThrow(`route node "a\\b" must not contain '\\'`);
  });

  it("refusesAPipe", () => {
    expect(() => requireValidNode("a|b")).toThrow(`route node "a|b" must not contain '|'`);
  });

  it("refusesALoneSurrogateInEitherHalfOrPosition", () => {
    for (const node of ["a\ud800", "\ud800a", "\udc00", "\udc00\ud800"]) {
      expect(() => requireValidNode(node), JSON.stringify(node)).toThrow("route node must not contain a lone surrogate");
    }
  });

  it("allowsOrdinaryNamesDotsInsideNamesAndWellFormedPairs", () => {
    for (const ok of ["gateway", "mcp:github.create_pull_request", "a.b", "...", ".a", "a..", "caf\u00e9", "\ud83d\ude00"]) {
      expect(() => requireValidNode(ok), ok).not.toThrow();
    }
  });
});
