// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class StampV1Test {

    @Test
    void signingBytesJoinFieldsInCanonicalOrder() {
        StampV1 s = new StampV1("gateway", "host1", "rid-1", 1761249600123L, "bindHash", "", "sig");
        byte[] expected = "gateway|host1|rid-1|1761249600123|bindHash|".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expected, s.signingBytes());
    }

    @Test
    void signerProducesStampThatVerifies() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        StampV1 s = StampSignerV1.sign("gateway", "host1", "rid-1", 1761249600123L, "bindHash", "", kp.getPrivate());

        assertEquals("gateway", s.svc());
        assertEquals("", s.prev());
        assertFalse(s.sig().isEmpty());
        assertTrue(Crypto.verify(kp.getPublic(), s.signingBytes(), Base64Url.decode(s.sig())));
    }

    @Test
    void sigDoesNotVerifyWhenAnyFieldChanges() {
        KeyPair kp = Crypto.generateEd25519KeyPair();
        StampV1 s = StampSignerV1.sign("gateway", "host1", "rid-1", 1761249600123L, "bindHash", "", kp.getPrivate());

        StampV1 tampered = new StampV1(s.svc(), s.inst(), s.rid(), 9999999999999L, s.bind(), s.prev(), s.sig());
        assertFalse(Crypto.verify(kp.getPublic(), tampered.signingBytes(), Base64Url.decode(tampered.sig())));
    }
}
