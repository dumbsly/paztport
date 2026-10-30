// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The service a certificate's subject names, read from the subject's DER encoding (RFC 5280's {@code Name}, encoded
 * as X.690 requires) rather than from any string the JDK renders it as, so that the rule is exactly the one the spec
 * states and does not move with a rendering:
 *
 * <ul>
 *   <li>The common names (attribute type 2.5.4.3) are counted across every RDN, and every value within a
 *       multi-valued RDN counts on its own, so {@code CN=a+CN=a} is two. Only a subject with exactly one names a
 *       service.</li>
 *   <li>That value must be a {@code DirectoryString}: UTF8String, PrintableString, TeletexString, UniversalString
 *       or BMPString, each well formed for its type. Any other type, IA5String and GeneralString among them, names
 *       no service.</li>
 * </ul>
 *
 * Anything else, a subject that is not a well-formed DER {@code Name} included, names no service, which is
 * {@code ""}: the peer check then fails closed rather than picking a name.
 */
final class SubjectService {

    /** The contents of the DER OBJECT IDENTIFIER 2.5.4.3, id-at-commonName. */
    private static final byte[] COMMON_NAME = {0x55, 0x04, 0x03};

    private static final int SEQUENCE = 0x30;
    private static final int SET = 0x31;
    private static final int OBJECT_IDENTIFIER = 0x06;
    private static final int UTF8_STRING = 0x0C;
    private static final int PRINTABLE_STRING = 0x13;
    private static final int TELETEX_STRING = 0x14;
    private static final int UNIVERSAL_STRING = 0x1C;
    private static final int BMP_STRING = 0x1E;

    /** An identifier in the high-tag-number form, which no type read here uses. */
    private static final int HIGH_TAG = -1;

    private SubjectService() {
    }

    /** The service {@code name}, a DER-encoded {@code Name}, names, or {@code ""} when it names none. */
    static String of(byte[] name) {
        try {
            Reader whole = new Reader(name, 0, name.length);
            Element sequence = whole.next(SEQUENCE);
            whole.end();
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
                        service = directoryString(value);
                    }
                }
            }
            return commonNames == 1 && service != null ? service : "";
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /** The text of a DirectoryString, or null for any other type or for one that is not well formed for its type. */
    private static String directoryString(Element value) {
        byte[] bytes = value.bytes();
        return switch (value.tag()) {
            case UTF8_STRING -> utf8(bytes);
            case PRINTABLE_STRING -> printable(bytes);
            case TELETEX_STRING -> new String(bytes, StandardCharsets.ISO_8859_1);
            case UNIVERSAL_STRING -> universal(bytes);
            case BMP_STRING -> bmp(bytes);
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

    /** Four octets per character, big-endian, each a Unicode scalar value. */
    private static String universal(byte[] bytes) {
        if (bytes.length % 4 != 0) {
            return null;
        }
        StringBuilder text = new StringBuilder(bytes.length / 4);
        for (int i = 0; i < bytes.length; i += 4) {
            long cp = (bytes[i] & 0xFFL) << 24 | (bytes[i + 1] & 0xFF) << 16 | (bytes[i + 2] & 0xFF) << 8
                    | bytes[i + 3] & 0xFF;
            if (cp > 0x10FFFF || cp >= 0xD800 && cp <= 0xDFFF) {
                return null;
            }
            text.appendCodePoint((int) cp);
        }
        return text.toString();
    }

    /** Two octets per character, big-endian, each in the Basic Multilingual Plane, so never a surrogate. */
    private static String bmp(byte[] bytes) {
        if (bytes.length % 2 != 0) {
            return null;
        }
        StringBuilder text = new StringBuilder(bytes.length / 2);
        for (int i = 0; i < bytes.length; i += 2) {
            char c = (char) ((bytes[i] & 0xFF) << 8 | bytes[i + 1] & 0xFF);
            if (Character.isSurrogate(c)) {
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
