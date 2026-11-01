// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, utf8 } from "../../src/crypto/crypto.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import { signKeyring } from "../../src/policy/keyring.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { readSessionRequest, replacementRequest, sessionRequest } from "../../src/session/request.ts";

/** Valid until 2100-01-01. */
const NOT_AFTER = 4_102_444_800_000;

function clientMaterial() {
  const policy = generateKeyPair();
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const { signedRoot } = buildPolicy([["session", "pi", "mcp:github.list_issues"]], 8, policy.privateKey, NOT_AFTER);
  const ring = signKeyring({ session: session.publicKey, pi: pi.publicKey }, policy.publicKey, policy.privateKey, NOT_AFTER);
  return { signedRoot, policyPublicKey: policy.publicKey, keyring: ring.services, keyringSig: ring.sig, keyringNotAfter: ring.notAfter };
}

describe("sessionRequest", () => {
  it("carriesTheClientsRootKeysAndAFreshNonce", () => {
    const client = clientMaterial();
    const a = sessionRequest(client);
    const b = sessionRequest({ ...client, signedRoot: null });
    expect(Object.keys(a)).toEqual(["clientRoot", "clientPolicyKey", "clientKeyring", "clientKeyringSig", "clientKeyringNotAfter", "nonce"]);
    expect(a).toMatchObject({
      clientRoot: client.signedRoot,
      clientPolicyKey: client.policyPublicKey,
      clientKeyring: client.keyring,
      clientKeyringSig: client.keyringSig,
      clientKeyringNotAfter: NOT_AFTER,
    });
    expect(a.clientRoot!.notAfter).toBe(NOT_AFTER);
    expect(b.clientRoot).toBeNull();
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe("replacementRequest", () => {
  it("dropsTheRootWithAFreshNonce", () => {
    const req = sessionRequest(clientMaterial());
    const r = replacementRequest(req);
    expect(Object.keys(r)).toEqual(Object.keys(req));
    expect(r).toEqual({ ...req, clientRoot: null, nonce: r.nonce });
    expect(r.nonce).not.toBe(req.nonce);
  });
});

describe("readSessionRequest", () => {
  const value = () => sessionRequest(clientMaterial());
  /** The token of `req` with its members changed by `edit`, written as the SDK writes a request. */
  const token = (req: object, edit: Record<string, unknown> = {}): string =>
    writeToken({ ...req, ...edit } as JsonValue);
  /** The token of exactly `text`'s bytes, which need not be canonical. */
  const bytes = (text: string): string => encode(utf8(text));
  it("readsWhatSessionRequestWrites", () => {
    const req = value();
    expect(readSessionRequest(token(req))).toEqual(req);
    expect(readSessionRequest(token({ ...req, clientRoot: null }))).toEqual({ ...req, clientRoot: null });
  });
  it("aMissingKeyringSignatureIsInvalid", () => {
    const { clientKeyringSig: _sig, ...missing } = value();
    expect(() => readSessionRequest(token(missing))).toThrow("no member clientKeyringSig");
    for (const bad of [null, 7, ["x"], {}]) {
      expect(() => readSessionRequest(token(missing, { clientKeyringSig: bad })), String(bad)).toThrow(
        "member clientKeyringSig is not a string",
      );
    }
    const empty = token(missing, { clientKeyringSig: "" });
    expect(() => readSessionRequest(empty)).toThrow("member clientKeyringSig is empty");
  });
  it("refusesClientMaterialWithoutNotAfter", () => {
    const { clientKeyringNotAfter: _w, ...noRingWindow } = value();
    const { notAfter: _r, ...root } = value().clientRoot!;
    expect(() => readSessionRequest(token(noRingWindow))).toThrow("no member clientKeyringNotAfter");
    expect(() => readSessionRequest(token(value(), { clientRoot: root }))).toThrow("no member notAfter");
  });
  it("keepsTheClientRootWholeAndTheKeyringWindow", () => {
    const req = value();
    const read = readSessionRequest(token(req));
    expect(read.clientRoot).toEqual(req.clientRoot);
    expect(read.clientKeyringNotAfter).toBe(NOT_AFTER);
  });
  it("aRequestInWireMemberOrderIsMalformed", () => {
    const req = value();
    const text = new TextDecoder().decode(decode(token(req)));
    const at = text.lastIndexOf(',"nonce":');
    const nonceFirst = `{${text.slice(at + 1, -1)},${text.slice(1, at)}}`;
    expect(readSessionRequest(bytes(text))).toEqual(req);
    expect(() => readSessionRequest(bytes(nonceFirst))).toThrow(MalformedJson);
    expect(() => readSessionRequest(bytes(`${text}\n`))).toThrow(MalformedJson);
  });
  it("aRequestWithAnExtraMemberIsMalformed", () => {
    const extra = token(value(), { serverEntry: "mcp-entry" });
    expect(() => readSessionRequest(extra)).toThrow("a member the object does not define");
    expect(() => readSessionRequest(token(value(), { clientRoot: { ...value().clientRoot!, note: "added" } }))).toThrow(
      "a member the object does not define",
    );
  });
  it("aNotAfterWrittenAnyOtherWayIsMalformed", () => {
    const text = new TextDecoder().decode(decode(token(value())));
    expect(text.split(`otAfter":${NOT_AFTER}`).length - 1).toBe(2);
    for (const bad of ["1.5", "-1", String(2 ** 53), `${NOT_AFTER}.0`, "4.1024448e12"]) {
      const written = bytes(text.replace(`otAfter":${NOT_AFTER}`, `otAfter":${bad}`));
      expect(() => readSessionRequest(written), bad).toThrow(MalformedJson);
    }
  });
  it("namesTheBadField", () => {
    expect(() => readSessionRequest(writeToken(null))).toThrow("not an object");
    expect(() => readSessionRequest(writeToken([]))).toThrow("not an object");
    expect(() => readSessionRequest("not*base64url")).toThrow(MalformedJson);
    expect(() => readSessionRequest(token(value(), { clientRoot: "x" }))).toThrow("not an object");
    const refusal = (edit: Record<string, unknown>) => () => readSessionRequest(token(value(), edit));
    expect(refusal({ clientKeyring: [] })).toThrow("member clientKeyring is not an object");
    expect(refusal({ clientKeyring: { a: 1 } })).toThrow("member clientKeyring holds a value that is not a string");
    for (const name of ["", ".", "..", "a/b", "a\\b", "a|b"]) {
      expect(refusal({ clientKeyring: { [name]: "k" } }), name).toThrow("member clientKeyring holds a name that is not a route node");
    }
    expect(refusal({ clientPolicyKey: 1 })).toThrow("member clientPolicyKey is not a string");
    expect(refusal({ nonce: null })).toThrow("member nonce is not a string");
    for (const bad of [null, "7", true, {}, []]) {
      const window = refusal({ clientKeyringNotAfter: bad });
      expect(window, String(bad)).toThrow("member clientKeyringNotAfter is not an integer");
    }
  });
  it("keepsAnInheritedNameAsAnOrdinaryKey", () => {
    const text = new TextDecoder().decode(decode(token(value())));
    const read = readSessionRequest(bytes(text.replace('"clientKeyring":{', '"clientKeyring":{"__proto__":"k",')));
    expect(Object.hasOwn(read.clientKeyring, "__proto__")).toBe(true);
  });
});
