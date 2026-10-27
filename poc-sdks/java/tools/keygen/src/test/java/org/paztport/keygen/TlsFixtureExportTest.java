// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.keygen;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Made the committed TLS fixtures in {@code spring/src/test/resources/tls}, and is kept as the record of how. It
 * is opt-in ({@code -Dpaztport.exportTlsFixtures=true -Dfixtures.out=<dir>}): the Spring mTLS tests need
 * certificates that exist before they run and do not expire under them, so they are generated once, valid for a
 * century, and committed. Like the vector export, a new run makes different keys and so a different set; replace
 * the whole directory together or not at all. The CA key is not written, so nothing can mint more of these. The
 * "foreign" CA and its {@code orders} certificate share a name with the real ones, to test that a certificate is
 * trusted for its issuer and not its name. These are test material only; real runs use {@link KeygenMain}.
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

        TlsIssuer.Ca foreign = TlsIssuer.newCa("foreign", CENTURY);
        Files.writeString(out.resolve("foreign-ca.crt"), TlsIssuer.pem(foreign.cert()));
        write(out, "foreign-orders", TlsIssuer.issue(foreign, "orders", CENTURY));
    }

    private static void write(Path out, String file, TlsIssuer.Issued issued) throws Exception {
        Files.writeString(out.resolve(file + ".crt"), TlsIssuer.pem(issued.cert()));
        Files.writeString(out.resolve(file + ".key"), TlsIssuer.pem(issued.keys().getPrivate()));
    }
}
