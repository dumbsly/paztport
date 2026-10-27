// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Made the committed TLS fixtures in {@code spring/src/test/resources/tls}, and is kept as the record of how. It
 * is opt-in ({@code -Dpaztport.exportTlsFixtures=true -Dfixtures.out=<dir>}): the Spring mTLS tests need
 * certificates that exist before they run and do not expire under them, so they are generated once, valid for a
 * century, and committed. Like the vector export, a new run makes different keys and so a different set; replace
 * the whole directory together or not at all. The CA key is not written, so nothing can mint more of these. The
 * "foreign" CA and its {@code orders} certificate share a name with the real ones, to test that a certificate is
 * trusted for its issuer and not its name. {@code nameless} is issued by the real CA with no common name at all, so
 * it names no service and a receiver must refuse it as a peer rather than skip the check. These are test material
 * only; real runs use {@link KeygenMain}.
 */
class TlsFixtureExportTest {

    private static final Duration CENTURY = Duration.ofDays(365L * 100);

    @Test
    @EnabledIfSystemProperty(named = "paztport.exportTlsFixtures", matches = "true")
    void export() throws Exception {
        Path out = Path.of(System.getProperty("fixtures.out", "target/tls-fixtures"));
        Files.createDirectories(out);

        TlsIssuer.Ca ca = TlsIssuer.newCa("shop", CENTURY);
        Files.writeString(out.resolve("ca.crt"), TlsIssuer.pem(ca.cert()));
        for (String name : new String[] {"gateway", "orders", "operator"}) {
            write(out, name, TlsIssuer.issue(ca, name, CENTURY));
        }
        // The test server is reached as localhost, so its certificate must name that too.
        write(out, "payment", TlsIssuer.issue(ca, "payment", CENTURY, "localhost", "127.0.0.1"));

        write(out, "nameless", nameless(ca));

        TlsIssuer.Ca foreign = TlsIssuer.newCa("foreign", CENTURY);
        Files.writeString(out.resolve("foreign-ca.crt"), TlsIssuer.pem(foreign.cert()));
        write(out, "foreign-orders", TlsIssuer.issue(foreign, "orders", CENTURY));
    }

    /**
     * A client certificate from {@code ca} whose subject is {@code O=shop}, with no CN. {@link TlsIssuer} always
     * writes a CN, as real identities must, so this one is built here.
     */
    private static TlsIssuer.Issued nameless(TlsIssuer.Ca ca) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        Instant now = Instant.now();
        BigInteger serial = new BigInteger(127, new SecureRandom()).add(BigInteger.ONE);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new JcaX509CertificateHolder(ca.cert()).getSubject(), serial,
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(CENTURY)), new X500Name("O=shop"),
                keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keys().getPrivate())));
        return new TlsIssuer.Issued(cert, keys);
    }

    private static void write(Path out, String file, TlsIssuer.Issued issued) throws Exception {
        Files.writeString(out.resolve(file + ".crt"), TlsIssuer.pem(issued.cert()));
        Files.writeString(out.resolve(file + ".key"), TlsIssuer.pem(issued.keys().getPrivate()));
    }
}
