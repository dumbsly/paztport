// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class EventEnvelopeTest {

    private final KeyPair key = Crypto.generateEd25519KeyPair();
    private final byte[] json = "{\"reason\":\"X\"}".getBytes(StandardCharsets.UTF_8);

    @Test
    void signedEnvelopeVerifiesAndCarriesThePayload() {
        EventEnvelope env = EventEnvelope.sign("payment", json, key.getPrivate());
        assertTrue(env.verifiesWith(key.getPublic()));
        assertArrayEquals(json, env.payloadBytes());
    }

    @Test
    void signatureCoversTheDomainPrefixThenThePayloadString() {
        EventEnvelope env = EventEnvelope.sign("payment", json, key.getPrivate());
        byte[] expected = ("paztport-event\n" + env.payload()).getBytes(StandardCharsets.UTF_8);
        assertTrue(Crypto.verify(key.getPublic(), expected, Base64Url.decode(env.sig())));
        // the bare payload, as a stamp-style signature would cover, does not verify
        assertFalse(Crypto.verify(key.getPublic(),
                env.payload().getBytes(StandardCharsets.UTF_8), Base64Url.decode(env.sig())));
    }

    @Test
    void tamperedOrMalformedEnvelopesDoNotVerify() {
        EventEnvelope env = EventEnvelope.sign("payment", json, key.getPrivate());
        assertFalse(new EventEnvelope("payment", env.payload() + "A", env.sig()).verifiesWith(key.getPublic()));
        assertFalse(new EventEnvelope("payment", env.payload(), "!!").verifiesWith(key.getPublic()));
        assertFalse(env.verifiesWith(Crypto.generateEd25519KeyPair().getPublic()));
        assertNull(new EventEnvelope("payment", "!!", env.sig()).payloadBytes());
    }
}
