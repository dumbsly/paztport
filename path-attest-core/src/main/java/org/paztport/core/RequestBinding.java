// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Binds a stamp to the request a hop actually sent: {@code bind} is the
 * base64url SHA-256 of {@code METHOD \n PATH \n BODY}. The verifier recomputes
 * this from the request it received and compares against the last stamp, so a
 * chain spliced onto a different payload no longer matches.
 */
public final class RequestBinding {

    private static final byte NL = (byte) '\n';

    private RequestBinding() {
    }

    public static String compute(String method, String path, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBytes(out, method.getBytes(StandardCharsets.UTF_8));
        out.write(NL);
        writeBytes(out, path.getBytes(StandardCharsets.UTF_8));
        out.write(NL);
        writeBytes(out, body);
        return Base64Url.encode(Crypto.sha256(out.toByteArray()));
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
        out.write(bytes, 0, bytes.length);
    }
}
