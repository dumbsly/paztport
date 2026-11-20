// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.paztport.http.HttpAnswer;

/**
 * Writes every refusal this starter makes, whichever filter or gate makes it, so that all of them leave the same
 * way. It is not for an application to use.
 */
public final class Refusals {

    /** The request attribute that holds the request's {@link Mark}. */
    private static final String IN_PLACE_OF_HANDLER = Refusals.class.getName() + ".inPlaceOfHandler";

    private Refusals() {
    }

    /**
     * Whether a refusal was made in place of the handler's answer, and the refusal itself while it is owed. One object
     * that a check marks, rather than an attribute it sets, because the DispatcherServlet removes the attributes an
     * include adds once the include returns, as the dispatch check's record is kept for the same reason. The inbound
     * filter holds the one it prepared and reads that, so a filter that later removes or replaces the attribute
     * cannot unmark the request.
     */
    public static final class Mark {
        private boolean marked;
        private HttpAnswer owed;

        private Mark() {
        }

        /** Whether a refusal was made in place of the handler's answer, so that answer is not the handler's. */
        public boolean marked() {
            return marked;
        }
    }

    /**
     * Gives the request the mark {@link #writeInPlaceOfHandler} sets, before any handler runs, so a mark made in an
     * include outlives it, and returns it. The inbound filter calls this before it passes the request on, and keeps
     * what it returns.
     */
    public static Mark prepareInPlaceOfHandler(HttpServletRequest request) {
        if (request.getAttribute(IN_PLACE_OF_HANDLER) instanceof Mark mark) {
            return mark;
        }
        Mark mark = new Mark();
        request.setAttribute(IN_PLACE_OF_HANDLER, mark);
        return mark;
    }

    /**
     * Writes {@code refusal} as {@link #write} does, and marks the request as answered by a refusal Paztport wrote in
     * place of the handler's answer, so the inbound filter does not attest it, whether or not the request names an
     * operation. For a check that runs as the handler is about to run and stops it. A handler reached by an include
     * cannot set the status, so there the refusal is only marked owed, and the inbound filter, which holds the
     * response, writes it once the chain returns ({@link #writeOwedInPlaceOfHandler}), as it does the dispatch
     * check's.
     */
    public static void writeInPlaceOfHandler(HttpServletRequest request, HttpServletResponse response,
            HttpAnswer refusal) throws IOException {
        Mark mark = prepareInPlaceOfHandler(request);
        mark.marked = true;
        if (request.getDispatcherType() == DispatcherType.INCLUDE) {
            mark.owed = refusal;
            return;
        }
        write(response, refusal);
    }

    /**
     * Writes the refusal {@link #writeInPlaceOfHandler} marked owed for a handler reached by an include, in place of
     * anything written around the include, once. A response already committed has gone out and cannot be refused;
     * its handler did not run, and nothing is attested for it.
     */
    public static void writeOwedInPlaceOfHandler(Mark mark, HttpServletResponse response) throws IOException {
        if (mark.owed != null && !response.isCommitted()) {
            HttpAnswer owed = mark.owed;
            mark.owed = null;
            response.resetBuffer();
            write(response, owed);
        }
    }

    /**
     * Sends {@code refusal} as {@code Content-Type: application/json} with no parameters. The body goes out as the
     * raw UTF-8 bytes the receiver made, through the output stream: a writer would have the container choose a
     * character encoding and add it to the header, and RFC 8259 defines no such parameter, since JSON exchanged
     * between systems is UTF-8 already. An application may have asked for one anyway, with a
     * forcing {@code CharacterEncodingFilter}, as an application may register, which sets the encoding before
     * Paztport's filters run and which the container would then append to the type; so any encoding already set is
     * cleared first. An answer with no body, such as the 503 for a cache that cannot answer, names no content type,
     * since a JSON type over nothing would be false.
     */
    public static void write(HttpServletResponse response, HttpAnswer refusal) throws IOException {
        response.setStatus(refusal.status());
        response.setCharacterEncoding((String) null);
        byte[] json = refusal.json();
        if (json.length > 0) {
            response.setContentType("application/json");
            response.getOutputStream().write(json);
        }
    }
}
