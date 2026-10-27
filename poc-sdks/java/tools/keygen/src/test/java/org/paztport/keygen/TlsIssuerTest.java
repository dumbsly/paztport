// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

class TlsIssuerTest {

    private static final Duration VALID = Duration.ofDays(825);

    @Test
    void aLeafVerifiesUnderItsCaAndNotUnderAnother() {
        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", VALID);
        TlsIssuer.Ca other = TlsIssuer.newCa("shop", VALID);
        TlsIssuer.Issued leaf = TlsIssuer.issue(ca, "orders", VALID);

        assertDoesNotThrow(() -> leaf.cert().verify(ca.keys().getPublic()));
        assertDoesNotThrow(() -> ca.cert().verify(ca.keys().getPublic()));
        org.junit.jupiter.api.Assertions.assertThrows(java.security.GeneralSecurityException.class,
                () -> leaf.cert().verify(other.keys().getPublic()));
    }

    @Test
    void theLeafNamesItselfInTheSubjectAndTheOnlySan() throws Exception {
        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", VALID);
        TlsIssuer.Issued leaf = TlsIssuer.issue(ca, "orders", VALID);

        assertEquals(new X500Principal("CN=orders"), leaf.cert().getSubjectX500Principal());
        assertEquals(new X500Principal("CN=shop CA"), ca.cert().getSubjectX500Principal());
        assertEquals(1, leaf.cert().getSubjectAlternativeNames().size());
        List<?> san = leaf.cert().getSubjectAlternativeNames().iterator().next().stream().toList();
        assertEquals(List.of(2, "orders"), san);
    }

    @Test
    void extraSansAreDnsNamesOrIpAddresses() throws Exception {
        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", VALID);
        TlsIssuer.Issued leaf = TlsIssuer.issue(ca, "payment", VALID, "localhost", "127.0.0.1");

        var sans = leaf.cert().getSubjectAlternativeNames().stream().map(List::copyOf).toList();
        assertTrue(sans.contains(List.of(2, "payment")));
        assertTrue(sans.contains(List.of(2, "localhost")));
        assertTrue(sans.contains(List.of(7, "127.0.0.1")));
    }

    @Test
    void onlyTheCaMayIssueAndALeafMayBeUsedAsServerAndClient() throws Exception {
        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", VALID);
        TlsIssuer.Issued leaf = TlsIssuer.issue(ca, "orders", VALID);

        assertEquals(0, ca.cert().getBasicConstraints());
        assertEquals(-1, leaf.cert().getBasicConstraints());
        boolean[] caUsage = ca.cert().getKeyUsage();
        assertTrue(caUsage[5] && caUsage[6], "keyCertSign and cRLSign");
        assertTrue(leaf.cert().getKeyUsage()[0], "digitalSignature");
        assertTrue(!leaf.cert().getKeyUsage()[5], "a leaf cannot sign certificates");
        List<String> eku = leaf.cert().getExtendedKeyUsage();
        assertTrue(eku.contains("1.3.6.1.5.5.7.3.1") && eku.contains("1.3.6.1.5.5.7.3.2"));
    }

    @Test
    void pemUsesTheStandardArmour() {
        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", VALID);

        assertTrue(TlsIssuer.pem(ca.cert()).startsWith("-----BEGIN CERTIFICATE-----\n"));
        assertTrue(TlsIssuer.pem(ca.keys().getPrivate()).startsWith("-----BEGIN PRIVATE KEY-----\n"));
        assertTrue(TlsIssuer.pem(ca.keys().getPrivate()).trim().endsWith("-----END PRIVATE KEY-----"));
    }

    @Test
    void nameIsALabelSoItCannotInjectSubjectFields() {
        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", VALID);
        assertThrows(IllegalArgumentException.class, () -> TlsIssuer.issue(ca, "a,O=x", VALID));
        assertThrows(IllegalArgumentException.class, () -> TlsIssuer.newCa("a,O=x", VALID));
    }

    @Test
    void leafAndCaCarryLinkingKeyIdentifiers() {
        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", VALID);
        TlsIssuer.Issued leaf = TlsIssuer.issue(ca, "orders", VALID);

        assertTrue(ca.cert().getExtensionValue("2.5.29.14") != null, "CA SKI");
        assertTrue(leaf.cert().getExtensionValue("2.5.29.14") != null, "leaf SKI");
        assertTrue(leaf.cert().getExtensionValue("2.5.29.35") != null, "leaf AKI");
        assertEquals(ca.cert().getSubjectX500Principal(), leaf.cert().getIssuerX500Principal());
    }
}
