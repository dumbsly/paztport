// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { routeFromRcv } from "../../src/internal/chain-checks.ts";
import { addressedTo, serviceOf } from "../../src/policy/routes.ts";
import type { Stamp } from "../../src/stamp/stamp.ts";

const stamp = (svc: string, rcv: string): Stamp =>
  ({ v: 3, svc, inst: `${svc}-1`, rid: "rid-1", ts: 1000, sess: "", rcv, bind: "b", infl: "", prev: "", sig: "x" }) as Stamp;

describe("operations in rcv", () => {
  it("serviceOfIsTheTextBeforeTheFirstHash", () => {
    expect(serviceOf("payment#charge")).toBe("payment");
    expect(serviceOf("payment")).toBe("payment");
    expect(serviceOf("payment#a#b")).toBe("payment");
  });

  it("addressedToTakesTheServiceOrOneOfItsOperations", () => {
    expect(addressedTo("payment", "payment")).toBe(true);
    expect(addressedTo("payment#charge", "payment")).toBe(true);
    expect(addressedTo("payment#", "payment")).toBe(false);
    expect(addressedTo("paymentx", "payment")).toBe(false);
    expect(addressedTo("search#find", "payment")).toBe(false);
    expect(addressedTo("payment", "payment#charge")).toBe(false);
  });

  it("routeFromRcvNamesTheOperationsAndLeavesTheLastOffWhenTheReceiverIsNotOnTheRoute", () => {
    const stamps = [stamp("gateway", "orders#createOrder"), stamp("orders", "payment#charge")];
    expect(routeFromRcv(stamps, true)).toBe("gateway/orders#createOrder/payment#charge");
    expect(routeFromRcv(stamps, false)).toBe("gateway/orders#createOrder");
  });
});
