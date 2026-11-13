// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;

/**
 * The SDK's Ed25519 answers {@code spec/vectors/ed25519.json} with another provider installed first. Bouncy Castle
 * checks the cofactored equation, so an SDK that took whichever provider sorts first would accept cases 21 and 22
 * here and throw on case 24. This module is the one with Bouncy Castle on its classpath, which is why the test
 * lives here and not beside the core replay.
 */
class Ed25519ProviderOrderTest {

    @BeforeEach
    void bouncyCastleFirst() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @AfterEach
    void removeBouncyCastle() {
        // no other test in this JVM sees the provider
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    void everyCaseGivesTheRecordedAnswer() {
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, Security.getProviders()[0].getName());
        List<String> wrong = new ArrayList<>();
        int count = 0;
        for (JsonValue c : JsonFields.array(JsonFields.object(JsonReader.file(vectorFile())), "cases")) {
            JsonValue.Obj o = JsonFields.object(c);
            count++;
            try {
                if (verifies(o) != JsonFields.bool(o, "valid")) {
                    wrong.add(JsonFields.string(o, "name"));
                }
            } catch (RuntimeException e) {
                // verify answers false and never throws, whatever the provider does
                wrong.add(JsonFields.string(o, "name") + " (threw " + e + ")");
            }
        }
        assertTrue(count > 0, "no cases read");
        assertEquals(List.of(), wrong);
    }

    /** As the core replay: a key that does not decode is a key that does not verify. */
    private static boolean verifies(JsonValue.Obj c) {
        PublicKey key;
        try {
            key = Crypto.decodePublicKey(Base64Url.decode(JsonFields.string(c, "publicKey")));
        } catch (IllegalArgumentException e) {
            return false;
        }
        return Crypto.verify(key, Base64Url.decode(JsonFields.string(c, "message")),
                Base64Url.decode(JsonFields.string(c, "signature")));
    }

    /** Walks up from the working directory, so the test does not depend on where Maven was started. */
    private static Path vectorFile() {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path d = dir; d != null; d = d.getParent()) {
            Path candidate = d.resolve("spec/vectors/ed25519.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("spec/vectors/ed25519.json not found above " + dir);
    }
}
