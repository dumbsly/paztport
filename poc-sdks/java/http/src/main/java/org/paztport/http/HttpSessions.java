// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

/**
 * The session handshake's names and body handling over HTTP, with no web framework. The request and reply are the
 * JSON forms {@link Sessions} already defines; this only fixes where they travel and how a bad body is read.
 *
 * <p>Parsing is as strict as {@link HttpV3}'s: bytes that are not exactly one JSON value, trailing tokens
 * included, are refused, so a body cannot carry a second value that another parser would read differently.
 */
public final class HttpSessions {

    /** The endpoint a client posts its {@link SessionRequest} to. */
    public static final String PATH = "/paztport/session";
    /** The error code for a body that is not a readable request. */
    public static final String INVALID_PARAMS = "INVALID_PARAMS";
    /** The error code for a request that does not open a session. */
    public static final String NO_SESSION = "NO_SESSION";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HttpSessions() {
    }

    /** Reads a request body, throwing {@link IllegalArgumentException} for anything a server must answer 400. */
    public static SessionRequest parseRequest(byte[] body) {
        return Sessions.parseRequest(body);
    }

    /** The body of a refusal: {@code {"error":"<code>"}}. */
    public static byte[] error(String code) {
        try {
            return MAPPER.writeValueAsBytes(JsonNodeFactory.instance.objectNode().put("error", code));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
