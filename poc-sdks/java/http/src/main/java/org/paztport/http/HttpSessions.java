// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

/**
 * The session handshake's names over HTTP, with no web framework: where the request and reply travel, and the
 * body of a refusal. The request and reply are the JSON forms {@link Sessions} defines. A server reads a request
 * body with {@link SessionRequest#parse(byte[])} and a client checks a reply body with
 * {@link Sessions#checkReply(byte[], SessionRequest, String, String, long)}; both refuse bytes that are not exactly
 * one JSON value, trailing tokens included, so a body cannot carry a second value that another parser would read
 * differently.
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

    /** The body of a refusal: {@code {"error":"<code>"}}. */
    public static byte[] error(String code) {
        try {
            return MAPPER.writeValueAsBytes(JsonNodeFactory.instance.objectNode().put("error", code));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
