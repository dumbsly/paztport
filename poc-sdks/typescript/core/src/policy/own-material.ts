// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { ReplyCert } from "../session/reply-cert.ts";
import { verifyKeyring, type SignedKeyring } from "./keyring.ts";
import { verifyRoot, type SignedRoot } from "./root.ts";
import { isNotAfter } from "./validity.ts";

/** A quarter of the default seven-day lifetime, 42 hours: a service warns at start-up when its keyring, root or certificate has no more than this left. */
export const WARN_WITHIN_MS = (7 * 86_400_000) / 4;

/** `notAfter` as the integer and, when it is in Date's range, its ISO time; never throws. */
export function describeNotAfter(notAfter: number): string {
  return Math.abs(notAfter) <= 8.64e15 ? `${notAfter} (${new Date(notAfter).toISOString()})` : `${notAfter}`;
}

/** What a service that loads its own policy holds: the policy key, its keyring and root, and for an entry the certificate for its key. */
export type OwnMaterial = {
  policyPublicKey: string;
  keyring: Record<string, string>;
  /** The policy key's signature over `keyring` and `keyringNotAfter`. */
  keyringSig: string;
  keyringNotAfter: number;
  signedRoot: SignedRoot;
  replyCert?: ReplyCert;
};

/** One reason not to start: which file, how it fails, and for EXPIRED its `notAfter`. */
export type OwnMaterialProblem =
  | { subject: "keyring" | "root"; kind: "DOES_NOT_VERIFY" }
  | { subject: "keyring" | "root"; kind: "EXPIRED"; notAfter: number };

/**
 * Everything wrong with the keyring and the root at `now`, the keyring's first and each in the order signature under
 * `policyPublicKey`, window: a service whose own material is bad refuses to start rather than degrade. A window that is
 * missing or not an integer in [0, 2^53 − 1] fails the signature, which is over it, and so is never judged as a time.
 */
export function checkOwnMaterial(m: OwnMaterial, now: number): OwnMaterialProblem[] {
  const problems: OwnMaterialProblem[] = [];
  const ring: SignedKeyring = { policy: m.policyPublicKey, services: m.keyring, sig: m.keyringSig, notAfter: m.keyringNotAfter };
  if (!Object.hasOwn(m, "keyringNotAfter") || !verifyKeyring(ring, m.policyPublicKey)) {
    problems.push({ subject: "keyring", kind: "DOES_NOT_VERIFY" });
  }
  if (isNotAfter(m.keyringNotAfter) && now > m.keyringNotAfter) {
    problems.push({ subject: "keyring", kind: "EXPIRED", notAfter: m.keyringNotAfter });
  }
  const root = m.signedRoot;
  if (!verifyRoot(root, m.policyPublicKey)) {
    problems.push({ subject: "root", kind: "DOES_NOT_VERIFY" });
  }
  if (Object.hasOwn(root, "notAfter") && isNotAfter(root.notAfter) && now > root.notAfter) {
    problems.push({ subject: "root", kind: "EXPIRED", notAfter: root.notAfter });
  }
  return problems;
}

/** A problem as an operator reads it, naming the file and the fix. */
export function describeOwnMaterialProblem(p: OwnMaterialProblem): string {
  switch (p.kind) {
    case "DOES_NOT_VERIFY":
      return `the ${p.subject} is not signed by policyPublicKey`;
    case "EXPIRED":
      return `the ${p.subject} expired at ${describeNotAfter(p.notAfter)}`;
  }
}

/** One warning per item (keyring, root, reply certificate) with no more than WARN_WITHIN_MS left at `now`, naming it and its `notAfter`. */
export function expiryWarnings(m: OwnMaterial, now: number): string[] {
  const items: [string, number | undefined][] = [
    ["keyring", m.keyringNotAfter],
    ["root", m.signedRoot.notAfter],
    ["replyCert", m.replyCert?.notAfter],
  ];
  return items
    .filter((item): item is [string, number] => item[1] !== undefined && item[1] - now <= WARN_WITHIN_MS)
    .map(([what, n]) => `paztport: the server's ${what} expires soon (notAfter ${describeNotAfter(n)}); re-sign it with the policy tool`);
}
