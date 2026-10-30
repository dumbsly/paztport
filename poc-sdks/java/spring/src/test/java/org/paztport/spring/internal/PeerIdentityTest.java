// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.paztport.core.verify.Peer;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Which certificate the servlet request holds for the client, and the address it came from. What a certificate names
 * is {@link PeerCert}'s, tested on its own.
 */
class PeerIdentityTest {

    private static X509Certificate fixture(String name) throws Exception {
        try (InputStream in = PeerIdentityTest.class.getResourceAsStream("/tls/" + name + ".crt")) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    @Test
    void withoutAClientCertificateThereIsNoPeer() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");

        assertNull(PeerIdentity.from(request));
        assertNull(PeerIdentity.cert(request));
    }

    @Test
    void anEmptyChainIsNoClientCertificate() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[0]);

        assertNull(PeerIdentity.cert(request));
    }

    @Test
    void theLeafCertificateNamesThePeerAndTheConnectionGivesItsAddress() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setRemoteAddr("172.18.0.5");
        request.setAttribute("jakarta.servlet.request.X509Certificate",
                new X509Certificate[] {fixture("orders"), fixture("gateway")});

        assertEquals(new Peer("orders", "172.18.0.5"), PeerIdentity.from(request));
    }

    @Test
    void aCertificateWithNoCommonNameIsAPeerThatNamesNoService() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setRemoteAddr("172.18.0.6");
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[] {fixture("nameless")});

        assertEquals(new Peer("", "172.18.0.6"), PeerIdentity.from(request), "still a peer, so the check runs");
    }

    @Test
    void theIssuerIsTheLeafCertificatesIssuerInRfc2253() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setAttribute("jakarta.servlet.request.X509Certificate",
                new X509Certificate[] {fixture("foreign-orders"), fixture("orders")});

        assertEquals("CN=foreign CA", PeerIdentity.cert(request).issuer());
    }
}
