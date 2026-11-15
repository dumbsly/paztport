// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.stamp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;

class StampTest {

    private static final KeyPair KEY = Crypto.generateEd25519KeyPair();

    /** wire.md, Fields and signed bytes: the example's stamp signs exactly the bytes the spec writes out. */
    @Test
    void theSpecsExampleSignsTheSpecsBytes() {
        Stamp s = new Stamp("pi", "pi-\u00e9", "rid-1", 1767225600000L, "", "local:read", "bind-2", "", "prev-2", "");
        assertArrayEquals(("paztport-stamp\n{\"bind\":\"bind-2\",\"ext\":\"\",\"inst\":\"pi-\u00e9\","
                + "\"prev\":\"prev-2\",\"rcv\":\"local:read\",\"rid\":\"rid-1\",\"sess\":\"\",\"svc\":\"pi\","
                + "\"ts\":1767225600000,\"v\":4}")
                .getBytes(StandardCharsets.UTF_8), s.signingBytes());
    }

    @Test
    void aFieldHoldingThePipeSignsAndVerifies() {
        Stamp s = Stamp.sign("a|b", "i", "r|1", 1, "", "x", "b", "", "", KEY.getPrivate());
        assertTrue(Crypto.verify(KEY.getPublic(), s.signingBytes(), Base64Url.decode(s.sig())));
        ParsedChain p = Chains.parse("[" + s.toJson() + "]");
        assertTrue(p.ok());
        assertEquals(s, p.stamps().get(0));
    }

    /**
     * Under version 3's joined fields, a quote and the members it seems to close could be told apart only by where the
     * delimiter fell. JCS escapes the quote, so the two stamps below sign different bytes.
     */
    @Test
    void twoStampsThatDifferOnlyInWhereAQuoteFallsDoNotShareSignedBytes() {
        Stamp one = new Stamp("pi", "a\",\"b", "r", 1, "", "x", "b", "", "", "");
        Stamp two = new Stamp("pi", "a", "r", 1, "", "x", "b", "", "", "");
        Stamp three = new Stamp("pi", "a\"", "\"b", 1, "", "x", "b", "", "", "");
        assertFalse(Arrays.equals(one.signingBytes(), two.signingBytes()));
        assertFalse(Arrays.equals(one.signingBytes(), three.signingBytes()));
        assertTrue(new String(one.signingBytes(), StandardCharsets.UTF_8).contains("\"inst\":\"a\\\",\\\"b\""));
    }

    @Test
    void aLoneSurrogateOrANoncharacterIsNeverSigned() {
        for (String bad : new String[] {"\ud800", "a\udc00", "\ufffe", "\ufdd0", "\uD83F\uDFFF"}) {
            for (int field = 0; field < 8; field++) {
                String[] f = {"pi", "i", "r", "", "x", "b", "", ""};
                f[field] = bad;
                int at = field;
                assertThrows(IllegalArgumentException.class,
                        () -> Stamp.sign(f[0], f[1], f[2], 1, f[3], f[4], f[5], f[6], f[7], KEY.getPrivate()),
                        "field " + at);
                Stamp unsigned = new Stamp(f[0], f[1], f[2], 1, f[3], f[4], f[5], f[6], f[7], "");
                assertThrows(IllegalArgumentException.class, unsigned::signingBytes, "field " + at);
            }
        }
    }

    /**
     * The stamp version is written once, as {@link Stamp#VERSION}. No other main source writes {@code "v"}
     * beside a 3 or a 4, or builds the integer 3 or 4 as a JSON value; in Stamp.java, the only code line holding a
     * 3 or a 4 is the constant.
     */
    @Test
    void theVersionIsWrittenOnce() throws IOException {
        Path main = Path.of("src/main/java/org/paztport/core");
        Path stamp = main.resolve("stamp/Stamp.java");
        assertTrue(Files.isRegularFile(stamp), stamp.toAbsolutePath().toString());
        Pattern version = Pattern.compile("\\b[34]\\b");
        Pattern jsonFour = Pattern.compile("JsonValue\\.Int\\(\\s*[34]\\s*\\)");
        List<String> found = new ArrayList<>();
        int scanned = 0;
        try (Stream<Path> files = Files.walk(main)) {
            for (Path file : (Iterable<Path>) files.filter(f -> f.toString().endsWith(".java"))::iterator) {
                scanned++;
                if (file.equals(stamp)) {
                    continue;
                }
                for (String line : Files.readAllLines(file)) {
                    if ((line.contains("\"v\"") && version.matcher(line).find()) || jsonFour.matcher(line).find()) {
                        found.add(main.relativize(file) + ": " + line.strip());
                    }
                }
            }
        }
        assertTrue(scanned > 50, "scanned the main sources: " + scanned);
        assertEquals(List.of(), found);
        List<String> code = Files.readAllLines(stamp).stream()
                .filter(l -> !l.strip().startsWith("//") && !l.strip().startsWith("/*") && !l.strip().startsWith("*"))
                .filter(l -> version.matcher(l).find()).map(String::strip).toList();
        assertEquals(List.of("public static final int VERSION = 4;"), code);
    }

    @Test
    void signatureVerifiesOverSigningBytes() {
        Stamp s = Stamp.sign("pi", "i", "r", 1, "", "x", "b", "", "", KEY.getPrivate());
        assertTrue(Crypto.verify(KEY.getPublic(), s.signingBytes(), Base64Url.decode(s.sig())));
    }

    @Test
    void toJsonIsJcs() {
        Stamp s = Stamp.sign("pi", "i", "r", 1, "", "x", "b", "e", "", KEY.getPrivate());
        assertEquals("{\"bind\":\"b\",\"ext\":\"e\",\"inst\":\"i\",\"prev\":\"\",\"rcv\":\"x\",\"rid\":\"r\","
                + "\"sess\":\"\",\"sig\":\"" + s.sig() + "\",\"svc\":\"pi\",\"ts\":1,\"v\":4}", s.toJson());
    }

    @Test
    void roundTrip() {
        Stamp s = Stamp.sign("pi", "i", "r", 1767225600000L, "sess", "x", "b", "n", "p", KEY.getPrivate());
        ParsedChain p = Chains.parse("[" + s.toJson() + "]");
        assertTrue(p.ok());
        assertEquals(s, p.stamps().get(0));
    }

    @Test
    void signRefusesANegativeTs() {
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", -1, "", "x", "b", "", "", KEY.getPrivate()));
    }

    @Test
    void signRefusesTsOutsideSafeRange() {
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", 9007199254740992L, "", "x", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", Long.MIN_VALUE, "", "x", "b", "", "", KEY.getPrivate()));
        assertThrows(IllegalArgumentException.class,
                () -> Stamp.sign("pi", "i", "r", Long.MAX_VALUE, "", "x", "b", "", "", KEY.getPrivate()));
        Stamp.sign("pi", "i", "r", 9007199254740991L, "", "x", "b", "", "", KEY.getPrivate());
        Stamp.sign("pi", "i", "r", 0, "", "x", "b", "", "", KEY.getPrivate());
    }
}
