// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;

class KeyGeneratorTest {

    /** The fixture keyring's validity window: 2100-01-01. */
    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static final List<String> SERVICES = List.of("gateway", "orders", "payment", "search");

    @Test
    void generatesAKeyPairForEveryServicePlusPolicy() {
        KeyGenerator.Result result = KeyGenerator.generate(SERVICES);

        assertEquals(SERVICES.size(), result.services().size());
        for (String svc : SERVICES) {
            assertNotNull(result.services().get(svc), "missing keypair for " + svc);
        }
        assertNotNull(result.policy(), "policy keypair must be generated");
    }

    @Test
    void eachServicePrivateKeySignsWhatItsPublicKeyVerifies() {
        KeyGenerator.Result result = KeyGenerator.generate(SERVICES);
        byte[] msg = "stamp".getBytes(StandardCharsets.UTF_8);

        for (String svc : SERVICES) {
            var kp = result.services().get(svc);
            byte[] sig = Crypto.sign(kp.getPrivate(), msg);
            assertTrue(Crypto.verify(kp.getPublic(), msg, sig), "key mismatch for " + svc);
        }
    }

    @Test
    void keyringHoldsEveryServiceAndThePolicyPublicKey() {
        KeyGenerator.Result result = KeyGenerator.generate(SERVICES);
        KeyringFile keyring = KeyGenerator.toKeyring(result, NOT_AFTER);

        assertEquals(SERVICES.size(), keyring.services().size());
        for (String svc : SERVICES) {
            assertTrue(keyring.services().containsKey(svc));
        }
        assertNotNull(keyring.policy());
        assertEquals(NOT_AFTER, keyring.notAfter());
        assertTrue(keyring.verifies(keyring.policy()));
    }

    @Test
    void keyringPublicKeysDecodeBackToTheGeneratedKeys() {
        KeyGenerator.Result result = KeyGenerator.generate(SERVICES);
        KeyringFile keyring = KeyGenerator.toKeyring(result, NOT_AFTER);

        byte[] fromKeyring = Crypto.encodePublicKey(
                Crypto.decodePublicKey(Base64Url.decode(keyring.services().get("gateway"))));
        byte[] original = Crypto.encodePublicKey(result.services().get("gateway").getPublic());
        assertArrayEquals(original, fromKeyring);
    }
}
