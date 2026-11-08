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
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Reads the request body once into memory so it can be hashed for binding in the
 * filter and still read again by the controller. Fine for the small bodies in this
 * POC.
 *
 * <p>Once the body's stream has been read the container no longer parses a
 * {@code POST} form body into parameters, so this serves them from the cached
 * bytes: the container's own parameters (the query's) first, then the form's
 * fields. Only {@code POST} is served here. On {@code PUT}, {@code PATCH} and
 * {@code DELETE} Boot's form content filter, which runs after this request is made,
 * adds the fields later from the cached bytes, and serving them here too would
 * double them.
 */
final class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private static final String FORM = "application/x-www-form-urlencoded";

    private final byte[] body;

    /** The form's fields as decoded in {@link #formCharset}; replaced when the encoding changes. */
    private Map<String, List<String>> form;

    private Charset formCharset;

    CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
    }

    byte[] cachedBody() {
        return body;
    }

    /**
     * This request, with the same body, headers, method and path, whose parameters are those its container holds,
     * the query's, and none from the body.
     */
    HttpServletRequest withQueryParametersOnly() {
        HttpServletRequest container = (HttpServletRequest) getRequest();
        return new HttpServletRequestWrapper(this) {
            @Override
            public String getParameter(String name) {
                return container.getParameter(name);
            }

            @Override
            public String[] getParameterValues(String name) {
                return container.getParameterValues(name);
            }

            @Override
            public Enumeration<String> getParameterNames() {
                return container.getParameterNames();
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                return container.getParameterMap();
            }
        };
    }

    @Override
    public String getParameter(String name) {
        String[] values = getParameterValues(name);
        return values == null ? null : values[0];
    }

    @Override
    public String[] getParameterValues(String name) {
        return getParameterMap().get(name);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(getParameterMap().keySet());
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        Map<String, List<String>> fields = formFields();
        if (fields.isEmpty()) {
            return super.getParameterMap();
        }
        Map<String, List<String>> merged = new LinkedHashMap<>();
        super.getParameterMap().forEach((name, values) -> merged.put(name, new ArrayList<>(List.of(values))));
        fields.forEach((name, values) -> merged.computeIfAbsent(name, n -> new ArrayList<>()).addAll(values));
        Map<String, String[]> map = new LinkedHashMap<>();
        merged.forEach((name, values) -> map.put(name, values.toArray(String[]::new)));
        return Collections.unmodifiableMap(map);
    }

    /** The fields of a {@code POST} form body, none for any other request. */
    private synchronized Map<String, List<String>> formFields() {
        if (!"POST".equals(getMethod()) || !isForm(getContentType())) {
            return Map.of();
        }
        Charset charset = getCharacterEncoding() != null
                ? Charset.forName(getCharacterEncoding())
                : StandardCharsets.ISO_8859_1;
        if (form == null || !charset.equals(formCharset)) {
            Map<String, List<String>> fields = new LinkedHashMap<>();
            for (String pair : new String(body, charset).split("&")) {
                int equals = pair.indexOf('=');
                String name = equals < 0 ? pair : pair.substring(0, equals);
                if (name.isEmpty()) {
                    continue;
                }
                String value = equals < 0 ? "" : pair.substring(equals + 1);
                try {
                    String decodedName = URLDecoder.decode(name, charset);
                    String decodedValue = URLDecoder.decode(value, charset);
                    fields.computeIfAbsent(decodedName, n -> new ArrayList<>()).add(decodedValue);
                } catch (IllegalArgumentException malformedEscape) {
                    // As the container does, leaves out a field whose escape is malformed.
                }
            }
            form = fields;
            formCharset = charset;
        }
        return form;
    }

    private static boolean isForm(String contentType) {
        if (contentType == null) {
            return false;
        }
        int end = contentType.indexOf(';');
        String mediaType = end < 0 ? contentType : contentType.substring(0, end);
        return FORM.equals(mediaType.strip().toLowerCase(Locale.ROOT));
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
