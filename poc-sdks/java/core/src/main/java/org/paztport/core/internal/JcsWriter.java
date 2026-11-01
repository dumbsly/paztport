// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.internal;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.paztport.core.encoding.Text;

/**
 * RFC 8785 JSON Canonicalization Scheme over a Jackson tree, written by hand so no library decides what the signed
 * bytes are. Only the kinds Paztport hashes are supported: objects, arrays, strings, booleans, null and integers
 * within &plusmn;(2^53&minus;1). Anything else (a fraction, a larger integer, a lone surrogate) throws, because the
 * TypeScript SDK would print such a number differently and the two would sign different bytes. That includes an
 * integral-valued float such as {@code 1.0}: TypeScript would accept it as 1, Java refuses it. The number Java judges
 * by value, a reply certificate's {@code notAfter}, is hashed from its parsed form, never handed here as received:
 * the client's reply check rewrites {@code notAfter} as the integer it parsed to, so both SDKs cover the same bytes.
 * Every other number is not judged by value and is refused here unless it is already an integer. A Java {@code null}
 * reference or a missing node is a caller's bug and throws; only a JSON null prints {@code null}.
 */
public final class JcsWriter {

    private static final BigInteger MAX_SAFE = BigInteger.valueOf((1L << 53) - 1);
    private static final BigInteger MIN_SAFE = MAX_SAFE.negate();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private JcsWriter() {
    }

    public static String canonicalize(JsonNode node) {
        StringBuilder sb = new StringBuilder();
        write(node, sb);
        return sb.toString();
    }

    public static byte[] bytes(JsonNode node) {
        return canonicalize(node).getBytes(StandardCharsets.UTF_8);
    }

    private static void write(JsonNode node, StringBuilder sb) {
        if (node == null || node.isMissingNode()) {
            throw new IllegalArgumentException("jcs: no value");
        } else if (node.isNull()) {
            sb.append("null");
        } else if (node.isTextual()) {
            string(node.textValue(), sb);
        } else if (node.isBoolean()) {
            sb.append(node.booleanValue() ? "true" : "false");
        } else if (node.isNumber()) {
            number(node, sb);
        } else if (node.isArray()) {
            sb.append('[');
            boolean first = true;
            for (JsonNode item : node) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(item, sb);
            }
            sb.append(']');
        } else if (node.isObject()) {
            List<String> names = new ArrayList<>();
            Iterator<String> it = node.fieldNames();
            while (it.hasNext()) {
                names.add(it.next());
            }
            // RFC 8785 (section 3.2.3) sorts property names by their UTF-16 code units, each taken as an unsigned
            // number, with no regard to locale. A Java char is such a unit, and compareTo compares the chars in turn.
            names.sort(String::compareTo);
            sb.append('{');
            for (int i = 0; i < names.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                string(names.get(i), sb);
                sb.append(':');
                write(node.get(names.get(i)), sb);
            }
            sb.append('}');
        } else {
            throw new IllegalArgumentException("jcs: unsupported node " + node.getNodeType());
        }
    }

    private static void number(JsonNode node, StringBuilder sb) {
        if (!node.isIntegralNumber()) {
            throw new IllegalArgumentException("jcs: non-integer number");
        }
        BigInteger v = node.bigIntegerValue();
        if (v.compareTo(MAX_SAFE) > 0 || v.compareTo(MIN_SAFE) < 0) {
            throw new IllegalArgumentException("jcs: integer outside the safe range");
        }
        sb.append(v);
    }

    private static void string(String s, StringBuilder sb) {
        if (!Text.isWellFormed(s)) {
            throw new IllegalArgumentException("jcs: lone surrogate");
        }
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append("\\u00").append(HEX[c >> 4]).append(HEX[c & 15]);
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
