// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.event;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

/**
 * The signed wrapper around an event on its way to the responder. The signature
 * covers the {@code payload} string exactly as sent, so the receiver verifies the
 * bytes it was given and never has to canonicalise JSON. The signed bytes carry a
 * domain prefix, so an event signature can never be mistaken for a stamp
 * signature made with the same key.
 *
 * @param signer  the service whose key signed the event
 * @param payload base64url of the event's JSON bytes
 * @param sig     base64url Ed25519 signature over {@link #signingBytes(String)} of {@code payload}
 */
public record EventEnvelope(String signer, String payload, String sig) {

    /** Domain separator prepended to the payload before signing. */
    public static final String DOMAIN = "paztport-event\n";

    public static EventEnvelope sign(String signer, byte[] eventJson, PrivateKey key) {
        String payload = Base64Url.encode(eventJson);
        return new EventEnvelope(signer, payload, Base64Url.encode(Crypto.sign(key, signingBytes(payload))));
    }

    /** The exact bytes that are signed: the domain prefix followed by the payload string. */
    public static byte[] signingBytes(String payload) {
        return (DOMAIN + payload).getBytes(StandardCharsets.UTF_8);
    }

    /** True only if {@code sig} is well-formed and valid for this payload under {@code key}. */
    public boolean verifiesWith(PublicKey key) {
        try {
            return Crypto.verify(key, signingBytes(payload), Base64Url.decode(sig));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** The event's JSON bytes, or null if the payload is not valid base64url. */
    public byte[] payloadBytes() {
        try {
            return Base64Url.decode(payload);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
