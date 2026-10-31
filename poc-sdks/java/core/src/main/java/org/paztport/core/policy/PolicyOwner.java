// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.session.ReplyCert;

/**
 * The checks a policy owner makes before it signs, in one place so that no tool can sign without them. Each
 * method signs only what it first confirmed was signed by this same policy key. Every one throws
 * {@link IllegalArgumentException}, having signed nothing the caller can use, when a check fails. Reading and
 * writing files, and naming them in a message, are the caller's.
 *
 * <p>Every message names the thing refused ("keyring ...", "root ..."), for the caller to put a file name before.
 *
 * <p>What these cannot check is the owner's to ensure: that no listed key has been retired since the keyring was
 * signed, that the keyring given is the current one, and that every route in a renewed tree is still allowed.
 */
public final class PolicyOwner {

    private PolicyOwner() {
    }

    /**
     * The keyring signed again until {@code notAfter}. It must verify, expired or not, under the policy key it
     * names, and that key must be {@code policyKey}'s: otherwise the re-signed keyring would not
     * verify under the key it names. Re-signing vouches that each listed key is still its service's current key; a
     * retired key needs a new keyring, not a renewed one.
     */
    public static KeyringFile renewKeyring(KeyringFile ring, long notAfter, PrivateKey policyKey) {
        if (ring.policy() == null || !ring.verifies(ring.policy())) {
            throw new IllegalArgumentException("keyring is not signed by its policy key");
        }
        KeyringFile renewed = ring.renewed(notAfter, policyKey);
        if (!renewed.verifies(ring.policy())) {
            throw new IllegalArgumentException("keyring is not signed by this policy key");
        }
        return renewed;
    }

    /**
     * The root signed again until {@code notAfter}, with the same {@code root} and {@code rootId} so existing proof
     * bundles stay valid. It must verify, expired or not, under {@code policyPublicKey}, the
     * base64url key of the policy key that will sign the renewal (a keyring's {@code policy}, once
     * {@link #renewKeyring} has accepted it), and {@code policyKey} must be that key's private half: otherwise the
     * renewed root would not verify under the key it was checked against. Renewing vouches that every route in the
     * tree is still allowed; a narrowed policy is a new tree, never a renewal.
     */
    public static SignedRoot renewRoot(SignedRoot root, String policyPublicKey, long notAfter, PrivateKey policyKey) {
        PublicKey publicKey = policyPublicKey(policyPublicKey);
        if (!root.verify(publicKey)) {
            throw new IllegalArgumentException("root is not signed by this policy key");
        }
        SignedRoot renewed = root.renewed(notAfter, policyKey);
        if (!renewed.verify(publicKey)) {
            throw new IllegalArgumentException("root is not signed by this policy key");
        }
        return renewed;
    }

    /**
     * A reply certificate for {@code svc}'s key in {@code ring}, valid until {@code notAfter}. The certificate
     * vouches that the key is {@code svc}'s in the keyring, so the keyring must verify under the policy key it
     * names, that key must be {@code policyKey}'s, and the keyring must hold a key for {@code svc}.
     */
    public static ReplyCert issueReplyCert(KeyringFile ring, String svc, long notAfter, PrivateKey policyKey) {
        if (ring.policy() == null || !ring.verifies(ring.policy())) {
            throw new IllegalArgumentException("keyring is not signed by its policy key");
        }
        String key = ring.services().get(svc);
        if (key == null) {
            throw new IllegalArgumentException("keyring has no key for service " + svc);
        }
        ReplyCert cert = ReplyCert.issue(ring.policy(), svc, key, notAfter, policyKey);
        if (!cert.verifies(ring.policy())) {
            throw new IllegalArgumentException("keyring is not signed by this policy key");
        }
        return cert;
    }

    /**
     * The base64url key {@link #renewRoot} checks against. A missing or malformed one is refused under the root's
     * name, as the other refusals are, since the root is what could not be checked.
     */
    private static PublicKey policyPublicKey(String policyPublicKey) {
        String refusal = "root cannot be checked: the policy key is not an Ed25519 public key";
        if (policyPublicKey == null) {
            throw new IllegalArgumentException(refusal);
        }
        try {
            return Crypto.decodePublicKey(Base64Url.decode(policyPublicKey));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(refusal, e);
        }
    }
}
