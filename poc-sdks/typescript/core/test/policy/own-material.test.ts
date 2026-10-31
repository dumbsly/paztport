// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair, sign, utf8 } from "../../src/crypto/crypto.ts";
import { canonicalize } from "../../src/encoding/jcs.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import {
  checkOwnMaterial,
  describeNotAfter,
  describeOwnMaterialProblem,
  expiryWarnings,
  WARN_WITHIN_MS,
  type OwnMaterial,
} from "../../src/policy/own-material.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { signReplyCert } from "../../src/session/reply-cert.ts";
import { encode } from "../../src/encoding/b64url.ts";

/** Valid until 2100-01-01. */
const FAR = 4_102_444_800_000;

function material(windows: { root?: number; keyring?: number; cert?: number } = {}): { m: OwnMaterial; policyPrivateKey: string } {
  const policy = generateKeyPair();
  const entry = generateKeyPair();
  const { signedRoot } = buildPolicy([["a", "b"]], 8, policy.privateKey, windows.root ?? FAR);
  const ring = signKeyring({ a: entry.publicKey }, policy.publicKey, policy.privateKey, windows.keyring ?? FAR);
  return {
    policyPrivateKey: policy.privateKey,
    m: {
      policyPublicKey: policy.publicKey,
      keyring: ring.services,
      keyringSig: ring.sig,
      keyringNotAfter: ring.notAfter,
      signedRoot,
      replyCert: signReplyCert(policy.publicKey, "a", entry.publicKey, windows.cert ?? FAR, policy.privateKey),
    },
  };
}

describe("describeNotAfter", () => {
  it("givesTheIntegerThenItsInstantWhenThereIsOne", () => {
    expect(describeNotAfter(5000)).toBe("5000 (1970-01-01T00:00:05.000Z)");
    expect(describeNotAfter(2 ** 53 - 1)).toBe(`${2 ** 53 - 1}`);
    expect(describeNotAfter(8.64e15)).toContain("+275760-09-13T00:00:00.000Z");
    expect(describeNotAfter(8.64e15 + 1)).toBe(`${8.64e15 + 1}`);
  });
});

describe("WARN_WITHIN_MS", () => {
  it("isAQuarterOfSevenDays", () => expect(WARN_WITHIN_MS).toBe(42 * 3_600_000));
});

describe("checkOwnMaterial", () => {
  const messages = (m: OwnMaterial, now: number) => checkOwnMaterial(m, now).map(describeOwnMaterialProblem);
  it("findsNothingWrongWithCurrentMaterial", () => {
    const { m } = material();
    expect(checkOwnMaterial(m, Date.now())).toEqual([]);
    expect(checkOwnMaterial(material({ root: 5, keyring: 5 }).m, 5)).toEqual([]);
  });
  it("namesEachFaultInTheKeyringThenTheRoot", () => {
    const { m } = material({ root: 5, keyring: 5 });
    expect(messages(m, 6)).toEqual([
      "the keyring expired at 5 (1970-01-01T00:00:00.005Z)",
      "the root expired at 5 (1970-01-01T00:00:00.005Z)",
    ]);
    const other = generateKeyPair();
    expect(messages({ ...m, policyPublicKey: other.publicKey }, 5)).toEqual([
      "the keyring is not signed by policyPublicKey",
      "the root is not signed by policyPublicKey",
    ]);
  });
  it("refusesMaterialWithoutNotAfterAsItRefusesAWindowThatIsNotAnInteger", () => {
    const { m, policyPrivateKey } = material();
    // each signed over its other fields alone, so only the missing window refuses it
    const keyringSig = encode(sign(policyPrivateKey, utf8("paztport-keyring\n" + canonicalize({ policy: m.policyPublicKey, services: m.keyring }))));
    const { keyringNotAfter: _k, ...noRingWindow } = { ...m, keyringSig };
    const { notAfter: _r, ...root } = m.signedRoot;
    const noRootWindow = { ...m, signedRoot: { ...root, sig: encode(sign(policyPrivateKey, utf8(`${root.rootId}|${root.root}`))) } };
    const notAnInteger = { ...m, keyringNotAfter: 1.5, signedRoot: { ...m.signedRoot, notAfter: 1.5 } };
    expect(checkOwnMaterial(noRingWindow as unknown as OwnMaterial, 1)).toEqual([{ subject: "keyring", kind: "DOES_NOT_VERIFY" }]);
    expect(checkOwnMaterial(noRootWindow as unknown as OwnMaterial, 1)).toEqual([{ subject: "root", kind: "DOES_NOT_VERIFY" }]);
    expect(checkOwnMaterial(notAnInteger, 1)).toEqual([
      { subject: "keyring", kind: "DOES_NOT_VERIFY" },
      { subject: "root", kind: "DOES_NOT_VERIFY" },
    ]);
  });
  it("reportsTheSubjectAndKind", () => {
    const { m } = material({ keyring: 5 });
    expect(checkOwnMaterial(m, 6)).toEqual([{ subject: "keyring", kind: "EXPIRED", notAfter: 5 }]);
  });
});

describe("expiryWarnings", () => {
  it("warnsOnceForEachItemWithNoMoreThanTheWarningSpanLeft", () => {
    const now = 1_000_000;
    const near = now + WARN_WITHIN_MS;
    const { m } = material({ keyring: near, root: near, cert: near });
    const w = expiryWarnings(m, now);
    expect(w).toHaveLength(3);
    expect(w[0]).toBe(`paztport: the server's keyring expires soon (notAfter ${near} (${new Date(near).toISOString()})); re-sign it with the policy tool`);
    expect(w[1]).toContain("root");
    expect(w[2]).toContain("replyCert");
    expect(expiryWarnings(material({ keyring: near + 1, root: near + 1, cert: near + 1 }).m, now)).toEqual([]);
  });
  it("leavesOutWhatTheMaterialDoesNotHave", () => {
    const { m } = material({ keyring: 1, root: 1 });
    const { replyCert: _c, ...bare } = m;
    expect(expiryWarnings(bare, 1)).toHaveLength(2);
  });
});
