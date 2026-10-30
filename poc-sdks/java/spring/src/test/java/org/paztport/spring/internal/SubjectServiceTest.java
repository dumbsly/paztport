// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

/** Names built by hand in DER, so each case is exactly the encoding it says, whatever the JDK would write. */
class SubjectServiceTest {

    private static final byte[] CN = {0x55, 0x04, 0x03};
    private static final byte[] O = {0x55, 0x04, 0x0A};

    /** One DER element, with its length in the shortest form. */
    private static byte[] tlv(int tag, byte[]... parts) {
        ByteArrayOutputStream contents = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            contents.writeBytes(p);
        }
        int n = contents.size();
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
        out.writeBytes(contents.toByteArray());
        return out.toByteArray();
    }

    private static byte[] attribute(byte[] type, int valueTag, byte[] value) {
        return tlv(0x30, tlv(0x06, type), tlv(valueTag, value));
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

    private static final byte[] SHOP = rdn(attribute(O, 0x0C, ascii("shop")));

    @Test
    void oneUtf8StringCommonNameIsTheService() {
        assertEquals("orders", SubjectService.of(name(SHOP, rdn(attribute(CN, 0x0C, ascii("orders"))))));
        assertEquals("zahlung-\u00fc", SubjectService.of(name(rdn(attribute(CN, 0x0C,
                "zahlung-\u00fc".getBytes(StandardCharsets.UTF_8))))));
    }

    @Test
    void onePrintableStringCommonNameIsTheService() {
        assertEquals("orders", SubjectService.of(name(rdn(attribute(CN, 0x13, ascii("orders"))))));
    }

    // RFC 5280 (4.1.2.4, 4.1.2.6) has conforming CAs use only UTF8String and PrintableString, so the other
    // DirectoryString choices name no service, however readable their text.
    @Test
    void aBmpStringCommonNameNamesNoService() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x1E,
                "orders".getBytes(StandardCharsets.UTF_16BE))))));
    }

    @Test
    void aTeletexStringCommonNameNamesNoService() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x14, ascii("orders"))))));
    }

    @Test
    void aUniversalStringCommonNameNamesNoService() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x1C, new byte[] {0, 0, 0, 'a', 0, 0, 0, 'b'})))));
    }

    @Test
    void anIa5StringCommonNameNamesNoService() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x16, ascii("orders"))))));
    }

    @Test
    void aGeneralStringCommonNameNamesNoService() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x1B, ascii("orders"))))));
    }

    @Test
    void twoCommonNamesInOneRdnNameNoServiceEvenWhenEqual() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x0C, ascii("a")),
                attribute(CN, 0x0C, ascii("a"))))));
    }

    @Test
    void twoCommonNamesInTwoRdnsNameNoServiceEvenWhenEqual() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x0C, ascii("a"))),
                rdn(attribute(CN, 0x0C, ascii("a"))))));
    }

    @Test
    void noCommonNameNamesNoService() {
        assertEquals("", SubjectService.of(name(SHOP)));
        assertEquals("", SubjectService.of(name()));
    }

    // A second common name counts even when its type would name no service, so it is never skipped over.
    @Test
    void aCommonNameOfAnotherTypeStillCounts() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x0C, ascii("orders"))),
                rdn(attribute(CN, 0x16, ascii("orders"))))));
    }

    @Test
    void aValueNotWellFormedForItsTypeNamesNoService() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x0C, new byte[] {(byte) 0xC0, (byte) 0x80})))),
                "an overlong UTF-8 form");
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x0C,
                new byte[] {(byte) 0xED, (byte) 0xA0, (byte) 0x80})))), "an encoded surrogate");
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x13, ascii("orders@shop"))))),
                "@ is not printable");
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x13, new byte[] {'a', (byte) 0xE9})))),
                "a byte past ASCII in a PrintableString");
    }

    @Test
    void anEncodingThatIsNotADerNameNamesNoService() {
        byte[] good = name(rdn(attribute(CN, 0x0C, ascii("orders"))));
        assertEquals("", SubjectService.of(new byte[0]));
        assertEquals("", SubjectService.of(Arrays.copyOf(good, good.length - 1)), "cut short");
        assertEquals("", SubjectService.of(Arrays.copyOf(good, good.length + 1)), "trailing octet");
        assertEquals("", SubjectService.of(name(tlv(0x30, attribute(CN, 0x0C, ascii("orders"))))),
                "an RDN that is not a SET");
        assertEquals("", SubjectService.of(name(rdn())), "an empty RDN");
        byte[] indefinite = good.clone();
        indefinite[1] = (byte) 0x80;
        assertEquals("", SubjectService.of(indefinite), "an indefinite length");
        byte[] longForm = new byte[good.length + 1];
        longForm[0] = 0x30;
        longForm[1] = (byte) 0x81;
        System.arraycopy(good, 1, longForm, 2, good.length - 1);
        assertEquals("", SubjectService.of(longForm), "a length not in its shortest form");
    }

    // The JDK keeps a principal's encoding as given, so PeerIdentity reads what the certificate carried.
    @Test
    void aPrincipalKeepsTheEncodingItWasGiven() {
        byte[] ia5 = name(SHOP, rdn(attribute(CN, 0x16, ascii("orders"))));
        assertArrayEquals(ia5, new X500Principal(ia5).getEncoded());
        assertEquals("", PeerIdentity.commonName(new X500Principal(ia5)));
        byte[] twice = name(rdn(attribute(CN, 0x0C, ascii("a")), attribute(CN, 0x0C, ascii("a"))));
        assertEquals("", PeerIdentity.commonName(new X500Principal(twice)));
    }
}
