// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.paztport.http.HttpAnswer;

/**
 * Writes every refusal this starter makes, whichever filter or gate makes it, so that all of them leave the same
 * way. It is not for an application to use.
 */
public final class Refusals {

    private Refusals() {
    }

    /**
     * Sends {@code refusal} as {@code Content-Type: application/json} with no parameters. The body goes out as the
     * raw UTF-8 bytes the receiver made, through the output stream: a writer would have the container choose a
     * character encoding and add it to the header, and RFC 8259 defines no such parameter, since JSON exchanged
     * between systems is UTF-8 already. An application may have asked for one anyway, with
     * {@code server.servlet.encoding.force-response}, which sets the encoding before any filter runs and which the
     * container would then append to the type; so any encoding already set is cleared first.
     */
    public static void write(HttpServletResponse response, HttpAnswer refusal) throws IOException {
        response.setStatus(refusal.status());
        response.setCharacterEncoding((String) null);
        response.setContentType("application/json");
        response.getOutputStream().write(refusal.json());
    }
}
