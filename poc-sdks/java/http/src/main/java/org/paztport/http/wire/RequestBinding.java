// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.encoding.Text;

/**
 * Binds a stamp to the request a hop actually sent: {@code bind} is the
 * base64url SHA-256 of {@code METHOD \n PATH \n BODY}. This HTTP extension
 * recomputes it from the request the receiver got, and the core verifier only
 * compares it against the last stamp, so a chain spliced onto a different payload no longer matches.
 */
public final class RequestBinding {

    private static final byte NL = (byte) '\n';

    private RequestBinding() {
    }

    /**
     * {@code target} is the raw path plus {@code ?} and the raw query when there is one, so a GET's query is bound
     * too. With no query the bytes are those of the method, path and body alone. A method or target with a lone
     * surrogate has no UTF-8 form, and encoding it would turn it into {@code ?}, so it is refused with
     * {@link IllegalArgumentException}.
     */
    public static String compute(String method, String target, byte[] body) {
        if (!Text.isWellFormed(method) || !Text.isWellFormed(target)) {
            throw new IllegalArgumentException("request: not well-formed Unicode");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBytes(out, method.getBytes(StandardCharsets.UTF_8));
        out.write(NL);
        writeBytes(out, target.getBytes(StandardCharsets.UTF_8));
        out.write(NL);
        writeBytes(out, body);
        return Base64Url.encode(Crypto.sha256(out.toByteArray()));
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
        out.write(bytes, 0, bytes.length);
    }
}
