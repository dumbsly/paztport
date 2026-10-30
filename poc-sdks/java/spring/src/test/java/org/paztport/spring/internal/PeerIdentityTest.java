// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.paztport.core.verify.Peer;
import org.springframework.mock.web.MockHttpServletRequest;

class PeerIdentityTest {

    private static X509Certificate fixture(String name) throws Exception {
        try (InputStream in = PeerIdentityTest.class.getResourceAsStream("/tls/" + name + ".crt")) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    @Test
    void theCommonNameIsTheServiceWhenThereIsExactlyOne() throws Exception {
        assertEquals("orders", PeerIdentity.service(signed(new X500Principal("CN=orders,O=shop").getEncoded())));
    }

    @Test
    void noCommonNameOrMoreThanOneNamesNoService() throws Exception {
        assertEquals("", PeerIdentity.service(signed(new X500Principal("O=shop").getEncoded())));
        assertEquals("", PeerIdentity.service(signed(new X500Principal("CN=a,CN=b").getEncoded())));
        assertEquals("", PeerIdentity.service(signed(new X500Principal("CN=a+CN=b").getEncoded())));
    }

    // Each of these the JDK parses, and its signature verifies, but the JDK's principal hands back an encoding it
    // built afresh, which reads as a well-formed CN=orders. The service is read from the certificate's own bytes, so
    // the spec's rule sees the subject as signed.
    @Test
    void aSubjectWithALengthNotInItsShortestFormNamesNoService() throws Exception {
        assertEquals("orders", PeerIdentity.service(signed(name(rdn(ORDERS)))), "the well-formed control");
        assertEquals("", PeerIdentity.service(signed(longForm(name(rdn(ORDERS))))), "the Name");
        assertEquals("", PeerIdentity.service(signed(name(longForm(rdn(ORDERS))))), "an RDN's SET");
        assertEquals("", PeerIdentity.service(signed(name(rdn(longForm(ORDERS))))), "an attribute's SEQUENCE");
        assertEquals("", PeerIdentity.service(signed(name(rdn(tlv(0x30, longForm(tlv(0x06, CN)),
                tlv(0x0C, ascii("orders"))))))), "the OBJECT IDENTIFIER");
        assertEquals("", PeerIdentity.service(signed(name(rdn(tlv(0x30, tlv(0x06, CN),
                longForm(tlv(0x0C, ascii("orders")))))))), "the common name's value");
    }

    @Test
    void aSubjectWithAnIndefiniteLengthNamesNoService() throws Exception {
        byte[] rdns = rdn(ORDERS);
        assertEquals("", PeerIdentity.service(signed(concat(new byte[] {0x30, (byte) 0x80}, rdns, new byte[] {0, 0}))));
    }

    // A trailing octet inside the subject never reaches the peer check: the JDK refuses the certificate as it parses
    // it, so the TLS layer cannot have verified one. The rule would name no service for it either.
    @Test
    void aSubjectWithATrailingOctetIsRefusedByTheJdkAndNamesNoService() throws Exception {
        byte[][] subjects = {
            tlv(0x30, rdn(ORDERS), new byte[] {0}),
            tlv(0x30, tlv(0x31, ORDERS, new byte[] {0})),
            tlv(0x30, rdn(tlv(0x30, tlv(0x06, CN), tlv(0x0C, ascii("orders")), new byte[] {0}))),
        };
        for (byte[] subject : subjects) {
            assertThrows(CertificateParsingException.class, () -> signed(subject));
            assertEquals("", SubjectService.of(subject));
        }
    }

    private static final byte[] CN = {0x55, 0x04, 0x03};
    private static final byte[] ORDERS = tlv(0x30, tlv(0x06, CN), tlv(0x0C, ascii("orders")));
    private static final byte[] ALGORITHM = tlv(0x30, tlv(0x06, new byte[] {0x2A, (byte) 0x86, 0x48, (byte) 0xCE,
        0x3D, 0x04, 0x03, 0x02}));
    private static final KeyPair CA = caKey();

    private static KeyPair caKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A certificate for {@code subject}, encoded exactly as given, signed and parsed by the JDK. It also checks that
     * the signature verifies and that the JDK hands back the {@code TBSCertificate} that was signed, byte for byte.
     */
    private static X509Certificate signed(byte[] subject) throws Exception {
        byte[] tbs = tlv(0x30, tlv(0xA0, tlv(0x02, new byte[] {2})), tlv(0x02, new byte[] {1}), ALGORITHM,
                name(rdn(tlv(0x30, tlv(0x06, CN), tlv(0x0C, ascii("shop CA"))))),
                tlv(0x30, tlv(0x17, ascii("260101000000Z")), tlv(0x17, ascii("360101000000Z"))), subject,
                CA.getPublic().getEncoded());
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(CA.getPrivate());
        signer.update(tbs);
        byte[] der = tlv(0x30, tbs, ALGORITHM, tlv(0x03, new byte[] {0}, signer.sign()));
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        certificate.verify(CA.getPublic());
        assertArrayEquals(tbs, certificate.getTBSCertificate());
        return certificate;
    }

    private static byte[] tlv(int tag, byte[]... parts) {
        byte[] contents = concat(parts);
        int n = contents.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (n < 0x80) {
            out.write(n);
        } else if (n < 0x100) {
            out.write(0x81);
            out.write(n);
        } else {
            out.write(0x82);
            out.write(n >> 8);
            out.write(n & 0xFF);
        }
        out.writeBytes(contents);
        return out.toByteArray();
    }

    /** {@code element}, whose length fits in one octet, with that length written in the long form instead. */
    private static byte[] longForm(byte[] element) {
        int n = element.length - 2;
        if (element[1] < 0 || n != element[1]) {
            throw new IllegalArgumentException("a short-form element only");
        }
        return concat(new byte[] {element[0], (byte) 0x81, (byte) n}, Arrays.copyOfRange(element, 2, element.length));
    }

    private static byte[] rdn(byte[]... attributes) {
        return tlv(0x31, attributes);
    }

    private static byte[] name(byte[]... rdns) {
        return tlv(0x30, rdns);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
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

    @Test
    void theIssuerIsTheLeafCertificatesIssuerInRfc2253() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        request.setAttribute("jakarta.servlet.request.X509Certificate",
                new X509Certificate[] {fixture("foreign-orders"), fixture("orders")});

        assertEquals("CN=foreign CA", PeerIdentity.issuer(request));
    }

    @Test
    void withoutAClientCertificateThereIsNoIssuer() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/pay");
        assertNull(PeerIdentity.issuer(request));
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[0]);
        assertNull(PeerIdentity.issuer(request));
    }
}
