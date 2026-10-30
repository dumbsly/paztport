// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.internal;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The service a certificate's subject names, read from the subject's DER encoding (RFC 5280's {@code Name}, encoded
 * as X.690 requires) as it stands in the certificate's own {@code TBSCertificate}, rather than from a string the JDK
 * renders it as or an encoding the JDK rebuilds from its parse, so that the rule is exactly the one the spec states
 * and is applied to the bytes the certificate's signature covers:
 *
 * <ul>
 *   <li>An attribute is a common name exactly when its OBJECT IDENTIFIER's contents are {@code 55 04 03}
 *       (2.5.4.3); any other contents, well formed or not, are some other attribute. The common names are counted
 *       across every RDN, and every value within a multi-valued RDN counts on its own, so {@code CN=a+CN=a} is two.
 *       Only a subject with exactly one names a service.</li>
 *   <li>That value's identifier octet must be exactly {@code 0x0C} (UTF8String) or {@code 0x13} (PrintableString),
 *       and the value well formed for its type: the two encodings of a DirectoryString RFC 5280 requires conforming
 *       CAs to use (section 4.1.2.6 for the subject, as 4.1.2.4 for the issuer), so the others need no decoding of
 *       their own. Any other identifier names no service: a constructed or high-tag-number form, and TeletexString,
 *       UniversalString, BMPString, IA5String and GeneralString, among others.</li>
 *   <li>The headers walked (the {@code Name}, each RDN, each attribute, its OBJECT IDENTIFIER and its value) must be
 *       DER: definite lengths in their shortest form, each within its parent, and nothing after a {@code Name} read
 *       on its own. Nothing inside a value is walked, so what another attribute's value holds is never checked.</li>
 * </ul>
 *
 * Anything else names no service, which is {@code ""}: the peer check then fails closed rather than picking a name.
 */
public final class SubjectService {

    /** The contents of the DER OBJECT IDENTIFIER 2.5.4.3, id-at-commonName. */
    private static final byte[] COMMON_NAME = {0x55, 0x04, 0x03};

    private static final int SEQUENCE = 0x30;
    private static final int SET = 0x31;
    private static final int INTEGER = 0x02;
    private static final int OBJECT_IDENTIFIER = 0x06;
    /** The identifier of a certificate's {@code [0] EXPLICIT} version: context-specific, constructed, tag 0. */
    private static final int VERSION = 0xA0;
    private static final int UTF8_STRING = 0x0C;
    private static final int PRINTABLE_STRING = 0x13;

    /** An identifier in the high-tag-number form, which no type read here uses. */
    private static final int HIGH_TAG = -1;

    private SubjectService() {
    }

    /**
     * The service the certificate whose DER {@code TBSCertificate} is {@code tbs} names, or {@code ""} when it names
     * none. The subject is taken from these bytes, which are the ones the certificate's signature covers, because a
     * parsed principal can hand back an encoding of its own (the JDK's {@code X500Principal.getEncoded()} rebuilds
     * one from its parse of a subject not in DER), and the rule is about the certificate's encoding, not one rebuilt
     * from it.
     *
     * <p>The fields before the subject (the optional {@code [0]} version, the serial number, the signature algorithm,
     * the issuer and the validity) are skipped by their headers alone: each must have the tag RFC 5280 gives it and a
     * definite length, in its shortest form, that stays within the {@code TBSCertificate}; what each holds is not
     * looked at. A {@code TBSCertificate} that cannot be walked as far as the subject names no service.
     */
    public static String ofCertificate(byte[] tbs) {
        try {
            Reader whole = new Reader(tbs, 0, tbs.length);
            Reader fields = whole.next(SEQUENCE).contents();
            whole.end();
            Element field = fields.next();
            if (field.tag() == VERSION) {
                field = fields.next();
            }
            if (field.tag() != INTEGER) {
                throw new IllegalArgumentException("no serial number");
            }
            fields.next(SEQUENCE); // signature
            fields.next(SEQUENCE); // issuer
            fields.next(SEQUENCE); // validity
            return service(fields.next(SEQUENCE));
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /** The service {@code name}, a DER-encoded {@code Name}, names, or {@code ""} when it names none. */
    public static String of(byte[] name) {
        try {
            Reader whole = new Reader(name, 0, name.length);
            Element sequence = whole.next(SEQUENCE);
            whole.end();
            return service(sequence);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /**
     * The service the {@code Name} whose header has been read as {@code sequence} names, or {@code ""}; a fault in
     * its contents is an {@link IllegalArgumentException}, which each caller turns into {@code ""}.
     */
    private static String service(Element sequence) {
        Reader rdns = sequence.contents();
        int commonNames = 0;
        String service = null;
        while (!rdns.atEnd()) {
            Reader rdn = rdns.next(SET).contents();
            if (rdn.atEnd()) {
                throw new IllegalArgumentException("an RDN holds at least one attribute");
            }
            while (!rdn.atEnd()) {
                Reader attribute = rdn.next(SEQUENCE).contents();
                Element type = attribute.next(OBJECT_IDENTIFIER);
                Element value = attribute.next();
                attribute.end();
                if (type.contentsAre(COMMON_NAME)) {
                    commonNames++;
                    service = text(value);
                }
            }
        }
        return commonNames == 1 && service != null ? service : "";
    }

    /**
     * The text of a UTF8String or PrintableString, or null for any other type, or for one that is not well formed for
     * its type.
     */
    private static String text(Element value) {
        byte[] bytes = value.bytes();
        return switch (value.tag()) {
            case UTF8_STRING -> utf8(bytes);
            case PRINTABLE_STRING -> printable(bytes);
            default -> null;
        };
    }

    private static String utf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /** X.680's PrintableString: letters, digits, space and {@code '()+,-./:=?}. */
    private static String printable(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length);
        for (byte b : bytes) {
            char c = (char) b;
            boolean allowed = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
                    || " '()+,-./:=?".indexOf(c) >= 0;
            if (!allowed) {
                return null;
            }
            text.append(c);
        }
        return text.toString();
    }

    /** One element: its tag (the identifier octet, or {@link #HIGH_TAG}) and where its contents lie. */
    private record Element(int tag, byte[] in, int start, int end) {

        Reader contents() {
            return new Reader(in, start, end);
        }

        byte[] bytes() {
            return Arrays.copyOfRange(in, start, end);
        }

        boolean contentsAre(byte[] expected) {
            return Arrays.equals(in, start, end, expected, 0, expected.length);
        }
    }

    /**
     * Reads the elements between two offsets, in X.690's distinguished encoding: definite lengths only, each in the
     * fewest octets. Every fault is an {@link IllegalArgumentException}.
     */
    private static final class Reader {

        private final byte[] in;
        private final int end;
        private int at;

        Reader(byte[] in, int start, int end) {
            this.in = in;
            this.at = start;
            this.end = end;
        }

        boolean atEnd() {
            return at == end;
        }

        void end() {
            if (!atEnd()) {
                throw new IllegalArgumentException("more than was expected");
            }
        }

        Element next(int expectedTag) {
            Element e = next();
            if (e.tag() != expectedTag) {
                throw new IllegalArgumentException("an unexpected tag");
            }
            return e;
        }

        Element next() {
            int tag = octet();
            if ((tag & 0x1F) == 0x1F) {
                // The high-tag-number form: the tag number follows, base 128, its last octet's top bit clear.
                int b;
                do {
                    b = octet();
                } while ((b & 0x80) != 0);
                tag = HIGH_TAG;
            }
            int length = length();
            if (length > end - at) {
                throw new IllegalArgumentException("contents past the end");
            }
            Element e = new Element(tag, in, at, at + length);
            at += length;
            return e;
        }

        private int length() {
            int first = octet();
            if (first < 0x80) {
                return first;
            }
            int count = first & 0x7F;
            if (count == 0 || count > 4) {
                throw new IllegalArgumentException("an indefinite or oversized length");
            }
            long length = 0;
            for (int i = 0; i < count; i++) {
                int b = octet();
                if (i == 0 && b == 0) {
                    throw new IllegalArgumentException("a length with a leading zero octet");
                }
                length = length << 8 | b;
            }
            if (length < 0x80 || length > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("a length not in its shortest form");
            }
            return (int) length;
        }

        private int octet() {
            if (at >= end) {
                throw new IllegalArgumentException("past the end");
            }
            return in[at++] & 0xFF;
        }
    }
}
