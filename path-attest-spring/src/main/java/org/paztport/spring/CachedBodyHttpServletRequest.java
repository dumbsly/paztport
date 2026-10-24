// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Reads the request body once into memory so it can be hashed for binding in the
 * filter and still read again by the controller. Fine for the small JSON bodies
 * in this POC.
 */
final class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
    }

    byte[] cachedBody() {
        return body;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream source = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return source.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                throw new UnsupportedOperationException();
            }

            @Override
            public int read() {
                return source.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        Charset charset = getCharacterEncoding() != null
                ? Charset.forName(getCharacterEncoding())
                : StandardCharsets.UTF_8;
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), charset));
    }

    static byte[] readAll(HttpServletRequest request) throws IOException {
        try (var in = request.getInputStream()) {
            return in.readAllBytes();
        }
    }
}
