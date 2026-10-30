// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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

    // Only the contents 55 04 03 make a common name. Any other OBJECT IDENTIFIER contents, even ones that would decode
    // to 2.5.4.3 if read leniently or that are not a well-formed OID at all, are some other attribute.
    @Test
    void anAttributeIsACommonNameExactlyWhenItsOidContentsAre550403() {
        byte[] orders = rdn(attribute(CN, 0x0C, ascii("orders")));
        assertEquals("orders", SubjectService.of(name(rdn(attribute(new byte[] {0x55, 0x04, (byte) 0x80, 0x03}, 0x0C,
                ascii("evil"))), orders)), "a non-minimal 2.5.4.3 is another attribute");
        assertEquals("orders", SubjectService.of(name(rdn(attribute(new byte[0], 0x0C, ascii("evil"))), orders)),
                "an empty OID is another attribute");
        assertEquals("", SubjectService.of(name(rdn(attribute(new byte[] {0x55, 0x04}, 0x0C, ascii("orders"))))),
                "a prefix of 2.5.4.3 is not a common name");
    }

    @Test
    void theValuesIdentifierOctetMustBeExactlyUtf8StringOrPrintableString() {
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x2C, tlv(0x0C, ascii("orders")))))),
                "a constructed UTF8String");
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x33, tlv(0x13, ascii("orders")))))),
                "a constructed PrintableString");
        assertEquals("", SubjectService.of(name(rdn(tlv(0x30, tlv(0x06, CN),
                new byte[] {0x1F, 0x0C, 0x06, 'o', 'r', 'd', 'e', 'r', 's'})))), "a high-tag-number form of tag 12");
        assertEquals("", SubjectService.of(name(rdn(attribute(CN, 0x8C, ascii("orders"))))),
                "a context-specific tag 12");
    }

    // The rule walks the headers down to each value and no further, so it never checks what another attribute's
    // value holds, however it is encoded.
    @Test
    void whatAnotherAttributesValueHoldsIsNotChecked() {
        byte[] nonMinimalInside = {0x04, (byte) 0x81, 0x01, 'x'};
        byte[] indefiniteInside = {0x24, (byte) 0x80, 0x04, 0x01, 'x', 0x00, 0x00};
        byte[] orders = rdn(attribute(CN, 0x0C, ascii("orders")));
        assertEquals("orders", SubjectService.of(name(rdn(attribute(O, 0x30, nonMinimalInside)), orders)));
        assertEquals("orders", SubjectService.of(name(rdn(attribute(O, 0x30, indefiniteInside)), orders)));
        assertEquals("orders", SubjectService.of(name(rdn(attribute(O, 0x0C, new byte[] {(byte) 0xC0, (byte) 0x80})),
                orders)), "another attribute's string need not be well formed");
    }

    /** A {@code TBSCertificate} holding {@code subject}: the fields before it well formed, their contents made up. */
    private static byte[] tbs(boolean version, byte[] subject) {
        byte[] versionField = version ? tlv(0xA0, tlv(0x02, new byte[] {2})) : new byte[0];
        return tlv(0x30, versionField, tlv(0x02, new byte[] {1}), ALGORITHM, ISSUER, VALIDITY, subject,
                tlv(0x30, tlv(0x30, tlv(0x06, new byte[] {0x2A})), tlv(0x03, new byte[] {0})));
    }

    private static final byte[] ALGORITHM = tlv(0x30, tlv(0x06, new byte[] {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D,
        0x04, 0x03, 0x02}));
    private static final byte[] ISSUER = name(rdn(attribute(CN, 0x0C, ascii("shop CA"))));
    private static final byte[] VALIDITY = tlv(0x30, tlv(0x17, ascii("260101000000Z")),
            tlv(0x17, ascii("360101000000Z")));
    private static final byte[] ORDERS = name(SHOP, rdn(attribute(CN, 0x0C, ascii("orders"))));

    @Test
    void aCertificatesSubjectIsReadFromItsTbsCertificateWithOrWithoutAVersion() {
        assertEquals("orders", SubjectService.ofCertificate(tbs(true, ORDERS)));
        assertEquals("orders", SubjectService.ofCertificate(tbs(false, ORDERS)), "a v1 certificate has no version");
    }

    @Test
    void theSubjectInATbsCertificateIsHeldToTheSameRule() {
        assertEquals("", SubjectService.ofCertificate(tbs(true, name(rdn(attribute(CN, 0x16, ascii("orders")))))),
                "an IA5String");
        assertEquals("", SubjectService.ofCertificate(tbs(true, longForm(ORDERS))),
                "a length not in its shortest form");
    }

    // The fields before the subject are passed over by their headers alone, so a made-up issuer or validity is no
    // concern of this rule; the TLS layer has already judged the certificate.
    @Test
    void whatTheFieldsBeforeTheSubjectHoldIsNotChecked() {
        byte[] t = tlv(0x30, tlv(0xA0, new byte[] {(byte) 0xFF}), tlv(0x02, new byte[] {(byte) 0x81, 0x01}),
                tlv(0x30, new byte[] {0x04, (byte) 0x81, 0x01, 'x'}), tlv(0x30),
                tlv(0x30, new byte[] {0x24, (byte) 0x80}), ORDERS);
        assertEquals("orders", SubjectService.ofCertificate(t));
    }

    @Test
    void aTbsCertificateThatCannotBeWalkedToTheSubjectNamesNoService() {
        byte[] good = tbs(true, ORDERS);
        assertEquals("", SubjectService.ofCertificate(new byte[0]), "empty");
        assertEquals("", SubjectService.ofCertificate(ORDERS.clone()), "a Name, not a TBSCertificate");
        assertEquals("", SubjectService.ofCertificate(Arrays.copyOf(good, good.length + 1)), "a trailing octet");
        assertEquals("", SubjectService.ofCertificate(Arrays.copyOf(good, good.length - 1)), "cut short");
        byte[] notSequence = good.clone();
        notSequence[0] = 0x31;
        assertEquals("", SubjectService.ofCertificate(notSequence), "not a SEQUENCE");
        assertEquals("", SubjectService.ofCertificate(indefinite(good)), "an indefinite TBSCertificate");
        assertEquals("", SubjectService.ofCertificate(tlv(0x30, tlv(0xA0, tlv(0x02, new byte[] {2})),
                tlv(0x04, new byte[] {1}), ALGORITHM, ISSUER, VALIDITY, ORDERS)), "no serial number");
        assertEquals("", SubjectService.ofCertificate(tlv(0x30, tlv(0x02, new byte[] {1}), ALGORITHM, ISSUER,
                VALIDITY)), "no subject");
        assertEquals("", SubjectService.ofCertificate(tlv(0x30, tlv(0x02, new byte[] {1}), ALGORITHM, ISSUER,
                tlv(0x31, VALIDITY), ORDERS)), "a validity that is not a SEQUENCE");
        assertEquals("", SubjectService.ofCertificate(tlv(0x30, tlv(0x02, new byte[] {1}), ALGORITHM,
                indefinite(ISSUER), VALIDITY, ORDERS)), "an indefinite issuer");
        assertEquals("", SubjectService.ofCertificate(tlv(0x30, tlv(0x02, new byte[] {1}), ALGORITHM,
                longForm(ISSUER), VALIDITY, ORDERS)), "an issuer length not in its shortest form");
        assertEquals("", SubjectService.ofCertificate(tlv(0x30, tlv(0x02, new byte[] {1}), ALGORITHM, ISSUER,
                new byte[] {0x30, 0x7F})), "a validity whose length runs past the TBSCertificate");
    }

    /** Where the contents of {@code element}, a DER element with a one-octet identifier, begin. */
    private static int contentsStart(byte[] element) {
        return element[1] >= 0 ? 2 : 2 + (element[1] & 0x7F);
    }

    /** {@code element}, whose length fits in one octet, with that length written in the long form instead. */
    private static byte[] longForm(byte[] element) {
        int n = element.length - 2;
        if (element[1] < 0 || n != element[1]) {
            throw new IllegalArgumentException("a short-form element only");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(element[0]);
        out.write(0x81);
        out.write(n);
        out.write(element, 2, n);
        return out.toByteArray();
    }

    /** {@code element} with an indefinite length, its contents closed by end-of-contents octets. */
    private static byte[] indefinite(byte[] element) {
        int start = contentsStart(element);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(element[0]);
        out.write(0x80);
        out.write(element, start, element.length - start);
        out.write(0);
        out.write(0);
        return out.toByteArray();
    }
}
