// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { routeOf, rulesRoute, rulesRouteNodes } from "../src/routes.ts";

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
});
