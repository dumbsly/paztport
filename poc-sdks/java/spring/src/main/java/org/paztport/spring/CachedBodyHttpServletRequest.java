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
 *
 * <p>Once a {@code POST} form's fields have been read as parameters, its body reads
 * as spent, an empty stream and reader, as the container's does once it has parsed
 * the form. Code that reads the body after the parameters, such as Boot's form
 * content filter behind Spring's method-override filter, which makes the request a
 * {@code PUT}, would otherwise add every field a second time. Before any parameter
 * is read the body still reads whole, and Spring builds a {@code POST} form's body
 * for a handler from its parameters.
 */
final class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private static final String FORM = "application/x-www-form-urlencoded";

    private final byte[] body;

    /** A {@code POST} form's parameters as decoded in the encoding they name; replaced when the encoding changes. */
    private Parameters form;

    /** Whether a {@code POST} form's fields have been read as parameters, after which the body reads as spent. */
    private volatile boolean spent;

    CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
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
        Parameters parameters = formParameters();
        if (parameters == null) {
            return super.getParameter(name);
        }
        List<String> values = parameters.values().get(name);
        return values == null ? null : values.get(0);
    }

    @Override
    public String[] getParameterValues(String name) {
        Parameters parameters = formParameters();
        if (parameters == null) {
            return super.getParameterValues(name);
        }
        List<String> values = parameters.values().get(name);
        return values == null ? null : values.toArray(String[]::new);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        Parameters parameters = formParameters();
        return parameters == null ? super.getParameterNames()
                : Collections.enumeration(parameters.values().keySet());
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        Parameters parameters = formParameters();
        return parameters == null ? super.getParameterMap() : parameters.map();
    }

    /**
     * The parameters of a {@code POST} form, the container's then the body's fields, built once for the encoding set
     * at the call, since the container's own do not change; null for any other request, whose parameters are the
     * container's alone.
     */
    private synchronized Parameters formParameters() {
        if (!"POST".equals(getMethod()) || !isForm(getContentType())) {
            return null;
        }
        spent = true;
        Charset charset = encoding(StandardCharsets.ISO_8859_1);
        if (form == null || !charset.equals(form.charset())) {
            Map<String, List<String>> merged = new LinkedHashMap<>();
            super.getParameterMap().forEach((name, values) -> merged.put(name, new ArrayList<>(List.of(values))));
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
                    merged.computeIfAbsent(decodedName, n -> new ArrayList<>()).add(decodedValue);
                } catch (IllegalArgumentException malformedEscape) {
                    // Leaves out a field whose escape is malformed rather than failing the whole request.
                }
            }
            form = Parameters.of(charset, merged);
        }
        return form;
    }

    /**
     * A form's parameters, built once: {@code values} serves {@link #getParameter}, {@link #getParameterValues}
     * (as a fresh array each call) and {@link #getParameterNames}, and cannot be changed; {@code map} is what
     * {@link #getParameterMap} answers. As on the container, the arrays in that map are shared by its callers, so a
     * caller that changes one changes only what the map answers, never the other three.
     */
    private record Parameters(Charset charset, Map<String, List<String>> values, Map<String, String[]> map) {

        static Parameters of(Charset charset, Map<String, List<String>> merged) {
            Map<String, List<String>> values = new LinkedHashMap<>();
            Map<String, String[]> map = new LinkedHashMap<>();
            merged.forEach((name, list) -> {
                values.put(name, List.copyOf(list));
                map.put(name, list.toArray(String[]::new));
            });
            return new Parameters(charset, Collections.unmodifiableMap(values), Collections.unmodifiableMap(map));
        }
    }

    /** The request's character encoding, or {@code fallback} when it sets none or names one this JVM lacks. */
    private Charset encoding(Charset fallback) {
        String label = getCharacterEncoding();
        if (label == null) {
            return fallback;
        }
        try {
            return Charset.forName(label);
        } catch (IllegalArgumentException unknown) {
            return fallback;
        }
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
        ByteArrayInputStream source = new ByteArrayInputStream(unread());
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
        Charset charset = encoding(StandardCharsets.UTF_8);
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(unread()), charset));
    }

    /** What is left to read of the body: none once its fields are parameters, all of it until then. */
    private byte[] unread() {
        return spent ? new byte[0] : body;
    }

    static byte[] readAll(HttpServletRequest request) throws IOException {
        try (var in = request.getInputStream()) {
            return in.readAllBytes();
        }
    }
}
