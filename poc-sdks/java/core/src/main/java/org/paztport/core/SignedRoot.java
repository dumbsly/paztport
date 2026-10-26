// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * The pinned policy root: the Merkle root plus its version, signed by the policy
 * key. Services pin this and reject any proof that does not resolve to
 * {@link #rootBytes()}. The signature covers {@code rootId|root} so a widened
 * tree cannot be swapped in without the policy key.
 */
public record SignedRoot(String rootId, String root, String sig) {

    public static SignedRoot sign(byte[] root, String rootId, PrivateKey policyKey) {
        String rootB64 = Base64Url.encode(root);
        String sig = Base64Url.encode(Crypto.sign(policyKey, signingBytes(rootId, rootB64)));
        return new SignedRoot(rootId, rootB64, sig);
    }

    public boolean verify(PublicKey policyKey) {
        return Crypto.verify(policyKey, signingBytes(rootId, root), Base64Url.decode(sig));
    }

    public byte[] rootBytes() {
        return Base64Url.decode(root);
    }

    public String encode() {
        return Base64Url.encode(Json.write(this));
    }

    public static SignedRoot decode(String text) {
        return Json.read(Base64Url.decode(text), SignedRoot.class);
    }

    private static byte[] signingBytes(String rootId, String rootB64) {
        return (rootId + "|" + rootB64).getBytes(StandardCharsets.UTF_8);
    }
}
