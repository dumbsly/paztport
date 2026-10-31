// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { ReplyCert } from "../session/reply-cert.ts";
import { verifyKeyring, type SignedKeyring } from "./keyring.ts";
import { verifyRoot, type SignedRoot } from "./root.ts";
import { isCurrent } from "./validity.ts";

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
  /** Absent for a keyring in the old form. */
  keyringNotAfter?: number;
  signedRoot: SignedRoot;
  replyCert?: ReplyCert;
};

/** One reason not to start: which file, how it fails, and for EXPIRED its `notAfter`. */
export type OwnMaterialProblem = {
  subject: "keyring" | "root";
  kind: "OLD_FORM" | "DOES_NOT_VERIFY" | "EXPIRED";
  notAfter?: number;
};

/**
 * Everything wrong with the keyring and the root at `now`, the keyring's first and each in the order old form,
 * signature under `policyPublicKey`, window: a service whose own material is bad refuses to start rather than degrade.
 */
export function checkOwnMaterial(m: OwnMaterial, now: number): OwnMaterialProblem[] {
  const problems: OwnMaterialProblem[] = [];
  if (m.keyringNotAfter === undefined) {
    problems.push({ subject: "keyring", kind: "OLD_FORM" });
  }
  const ring: SignedKeyring = { policy: m.policyPublicKey, services: m.keyring, sig: m.keyringSig };
  if (!verifyKeyring(m.keyringNotAfter !== undefined ? { ...ring, notAfter: m.keyringNotAfter } : ring, m.policyPublicKey)) {
    problems.push({ subject: "keyring", kind: "DOES_NOT_VERIFY" });
  }
  if (m.keyringNotAfter !== undefined && !isCurrent({ notAfter: m.keyringNotAfter }, now)) {
    problems.push({ subject: "keyring", kind: "EXPIRED", notAfter: m.keyringNotAfter });
  }
  const root = m.signedRoot;
  if (!Object.hasOwn(root, "notAfter")) {
    problems.push({ subject: "root", kind: "OLD_FORM" });
  }
  if (!verifyRoot(root, m.policyPublicKey)) {
    problems.push({ subject: "root", kind: "DOES_NOT_VERIFY" });
  }
  if (Object.hasOwn(root, "notAfter") && !isCurrent(root, now)) {
    problems.push({ subject: "root", kind: "EXPIRED", notAfter: root.notAfter });
  }
  return problems;
}

/** A problem as an operator reads it, naming the file and the fix. */
export function describeOwnMaterialProblem(p: OwnMaterialProblem): string {
  switch (p.kind) {
    case "OLD_FORM":
      return `the ${p.subject} is in the old form (no notAfter); re-sign it with the policy tool`;
    case "DOES_NOT_VERIFY":
      return `the ${p.subject} is not signed by policyPublicKey`;
    case "EXPIRED":
      return `the ${p.subject} expired at ${describeNotAfter(p.notAfter!)}`;
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
    .filter(([, n]) => n !== undefined && n - now <= WARN_WITHIN_MS)
    .map(([what, n]) => `paztport: the server's ${what} expires soon (notAfter ${describeNotAfter(n!)}); re-sign it with the policy tool`);
}
