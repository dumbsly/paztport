// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.paztport.core.Peer;
import org.springframework.mock.web.MockHttpServletRequest;

class PeerIdentityTest {

    private static X509Certificate fixture(String name) throws Exception {
        try (InputStream in = PeerIdentityTest.class.getResourceAsStream("/tls/" + name + ".crt")) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    @Test
    void theCommonNameIsTheServiceWhenThereIsExactlyOne() {
        assertEquals("orders", PeerIdentity.commonName(new X500Principal("CN=orders,O=shop")));
    }

    @Test
    void noCommonNameOrMoreThanOneNamesNoService() {
        assertEquals("", PeerIdentity.commonName(new X500Principal("O=shop")));
        assertEquals("", PeerIdentity.commonName(new X500Principal("CN=a,CN=b")));
        assertEquals("", PeerIdentity.commonName(new X500Principal("CN=a+CN=b")));
    }

    @Test
    void withoutAClientCertificateThereIsNoPeer() {
        assertNull(PeerIdentity.from(new MockHttpServletRequest("POST", "/pay")));
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
}
