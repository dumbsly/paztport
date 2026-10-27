// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Issues the mTLS identities: one certificate authority per organisation and a P-256 certificate per service.
 * The stamp keys prove what a request passed through; these certificates prove who is on the other end of the
 * connection, so the receiver can bind a stamp to its real peer. A leaf is valid as both server and client
 * because every mesh member plays both roles. The CA is constrained to path length 0, so it can sign leaves but
 * never another CA. Pure logic; file writing lives in {@link KeygenMain}.
 */
public final class TlsIssuer {

    private static final SecureRandom RANDOM = new SecureRandom();
    /** Back-dated so a certificate is valid on a host whose clock runs slightly behind. */
    private static final Duration SKEW = Duration.ofMinutes(5);

    private TlsIssuer() {
    }

    public record Ca(X509Certificate cert, KeyPair keys) {
    }

    public record Issued(X509Certificate cert, KeyPair keys) {
    }

    public static Ca newCa(String org, Duration validity) {
        try {
            KeyPair keys = newKeyPair();
            X500Name subject = new X500Name("CN=" + org + " CA");
            X509v3CertificateBuilder b = builder(subject, subject, keys, validity);
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            return new Ca(sign(b, keys.getPrivate()), keys);
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new IllegalStateException("could not create the CA", e);
        }
    }

    /**
     * Issues a leaf for {@code name}, which is its subject CN and a DNS SAN. Each extra SAN is a DNS name, or an
     * IP address when it parses as an IP literal.
     */
    public static Issued issue(Ca ca, String name, Duration validity, String... extraSans) {
        try {
            KeyPair keys = newKeyPair();
            X500Name issuer = new X500Name(ca.cert().getSubjectX500Principal().getName());
            X509v3CertificateBuilder b = builder(issuer, new X500Name("CN=" + name), keys, validity);
            List<GeneralName> sans = new ArrayList<>();
            sans.add(new GeneralName(GeneralName.dNSName, name));
            for (String san : extraSans) {
                sans.add(new GeneralName(isIpLiteral(san) ? GeneralName.iPAddress : GeneralName.dNSName, san));
            }
            b.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(sans.toArray(new GeneralName[0])));
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            b.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
            return new Issued(sign(b, ca.keys().getPrivate()), keys);
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new IllegalStateException("could not issue a certificate for " + name, e);
        }
    }

    public static String pem(X509Certificate cert) {
        try {
            return armour("CERTIFICATE", cert.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The key as PKCS#8, which is what the JDK's {@code PrivateKey.getEncoded()} gives for an EC key. */
    public static String pem(PrivateKey key) {
        return armour("PRIVATE KEY", key.getEncoded());
    }

    private static String armour(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }

    private static KeyPair newKeyPair() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        return g.generateKeyPair();
    }

    private static X509v3CertificateBuilder builder(X500Name issuer, X500Name subject, KeyPair keys, Duration validity) {
        Instant now = Instant.now();
        return new JcaX509v3CertificateBuilder(issuer, new BigInteger(127, RANDOM).add(BigInteger.ONE),
                Date.from(now.minus(SKEW)), Date.from(now.plus(validity)), subject, keys.getPublic());
    }

    private static X509Certificate sign(X509v3CertificateBuilder b, PrivateKey signer)
            throws OperatorCreationException, GeneralSecurityException {
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withECDSA").build(signer);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    /** True for a dotted IPv4 or a colon-separated IPv6 literal; a DNS name never has either shape. */
    private static boolean isIpLiteral(String s) {
        return s.matches("\\d{1,3}(\\.\\d{1,3}){3}") || (s.indexOf(':') >= 0 && s.matches("[0-9a-fA-F:.]+"));
    }
}
