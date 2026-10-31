// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.boundary;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.net.http.HttpClient;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.stamp.StamperV3;

/**
 * The egress's checks on its settings, as the builder makes them for any framework: the partner URL above all,
 * which the calls' stamps and owners must not cross in the clear, and the fault each refusal names. The checks on
 * this side's own root and keyring, and the starter's words for each, are tested with the client and the starter's
 * configuration.
 */
class BoundaryClientBuilderTest {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    private static final long NOT_AFTER = 4_102_444_800_000L;
    /** A validity window long past: 1970, one second in. */
    private static final long EXPIRED = 1_000L;

    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final KeyPair policy = Crypto.generateEd25519KeyPair();
    private final PolicyBuilder.Result built = PolicyBuilder.build(List.of(List.of("payment", "psp")), 4, NOT_AFTER,
            policy.getPrivate());
    private final HttpClient http = HttpClient.newHttpClient();

    @AfterEach
    void close() {
        http.close();
    }

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }

    /** Everything an egress needs, all of it sound, against {@code https://psp:8443}. */
    private BoundaryClient.Builder sound() {
        return BoundaryClient.builder()
                .stamper(new StamperV3("payment", "payment-1", payment.getPrivate(), false, () -> "unused",
                        System::currentTimeMillis))
                .bundle(built.bundles().get("payment"))
                .ownRoot(built.signedRoot())
                .ownKeyring(KeyringFile.sign(Map.of("payment", pub(payment)), pub(policy), NOT_AFTER,
                        policy.getPrivate()))
                .ownPolicyKey(pub(policy))
                .partner("psp")
                .partnerUrl(URI.create("https://psp:8443"))
                .pinnedPartnerKey(pub(Crypto.generateEd25519KeyPair()))
                .blindingKey(new byte[BoundaryInfluence.KEY_LENGTH])
                .http(http)
                .sessionIdleMs(600_000);
    }

    private static BoundaryClient.Fault fault(BoundaryClient.Builder builder) {
        return assertThrows(BoundaryClient.InvalidSetting.class, builder::build).fault();
    }

    @Test
    void soundSettingsBuildWithTheDefaultReadTimeout() {
        BoundaryClient client = sound().build();

        assertEquals(Duration.ofSeconds(30), client.readTimeout());
        assertEquals(BoundaryClient.DEFAULT_READ_TIMEOUT, client.readTimeout());
    }

    @Test
    void onlyAnHttpsPartnerUrlIsTaken() {
        for (String url : List.of("http://psp:8080", "ftp://psp", "//psp:8443", "psp:8443")) {
            BoundaryClient.InvalidSetting refused = assertThrows(BoundaryClient.InvalidSetting.class,
                    () -> sound().partnerUrl(URI.create(url)).build(), url);
            assertEquals(BoundaryClient.Fault.NOT_HTTPS, refused.fault(), url);
            assertEquals("the partner URL must be an https URL: " + url, refused.getMessage());
        }
        sound().partnerUrl(URI.create("HTTPS://psp:8443/")).build();
    }

    @Test
    void thePartnerUrlIsAnOriginOnly() {
        for (String url : List.of("https://psp:8443/pay", "https://psp:8443?x=1", "https://psp:8443#top",
                "https:psp")) {
            assertEquals(BoundaryClient.Fault.NOT_AN_ORIGIN, fault(sound().partnerUrl(URI.create(url))), url);
        }
    }

    @Test
    void eachOtherRefusalNamesItsFault() {
        assertEquals(BoundaryClient.Fault.KEY_LENGTH, fault(sound().blindingKey(new byte[31])));
        assertEquals(BoundaryClient.Fault.KEY_LENGTH, fault(sound().blindingKey(null)));
        assertEquals(BoundaryClient.Fault.READ_TIMEOUT, fault(sound().readTimeout(Duration.ZERO)));
        assertEquals(BoundaryClient.Fault.UNNAMED_PARTNER, fault(sound().partner("")));
        for (String svc : Arrays.asList("", null)) {
            assertEquals(BoundaryClient.Fault.UNNAMED_EGRESS, fault(sound().stamper(new StamperV3(svc, "payment-1",
                    payment.getPrivate(), false, () -> "unused", System::currentTimeMillis))), svc);
        }
        assertEquals(BoundaryClient.Fault.IDLE_PERIOD, fault(sound().sessionIdleMs(0)));
        assertEquals(BoundaryClient.Fault.OWN_UNVERIFIED,
                fault(sound().ownPolicyKey(pub(Crypto.generateEd25519KeyPair()))));
        // The URL comes first: a plain one is refused as such whatever else is wrong.
        assertEquals(BoundaryClient.Fault.NOT_HTTPS,
                fault(sound().partnerUrl(URI.create("http://psp")).sessionIdleMs(0).blindingKey(null)));
    }

    // The partner would judge an expired root or keyring unsafe, so none is taken that could only ever open unsafe
    // sessions.
    @Test
    void expiredOwnMaterialIsRefused() {
        SignedRoot root = built.signedRoot();
        Map<String, String> services = Map.of("payment", pub(payment));

        assertEquals(BoundaryClient.Fault.OWN_EXPIRED, fault(sound().ownRoot(
                SignedRoot.sign(root.rootBytes(), root.rootId(), EXPIRED, policy.getPrivate()))));
        assertEquals(BoundaryClient.Fault.OWN_EXPIRED, fault(sound().ownKeyring(
                KeyringFile.sign(services, pub(policy), EXPIRED, policy.getPrivate()))));
    }

    @Test
    void aMissingSettingIsANullPointer() {
        assertThrows(NullPointerException.class, () -> sound().partnerUrl(null).build());
        assertThrows(NullPointerException.class, () -> sound().http(null).build());
    }
}
