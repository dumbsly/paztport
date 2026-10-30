// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.paztport.core.session.SessionReply;
import org.paztport.core.session.SessionRequest;
import org.paztport.core.session.Sessions;

/**
 * The session handshake over HTTP, with no web framework: where the request and reply travel, the body of a
 * refusal, and a partner's answer to one request ({@link #serve}). The request and reply are the JSON forms
 * {@link Sessions} defines. A server reads a request body with {@link SessionRequest#parse(byte[])} and a client checks
 * a reply body with {@link Sessions#checkReply(byte[], SessionRequest, String, String, long)}; both refuse bytes that
 * are not exactly one JSON value, trailing tokens included, so a body cannot carry a second value that another parser
 * would read differently.
 */
public final class HttpSessions {

    /** The endpoint a client posts its {@link SessionRequest} to. */
    public static final String PATH = "/paztport/session";
    /** The error code for a body that is not a readable request. */
    public static final String INVALID_PARAMS = "INVALID_PARAMS";
    /** The error code for a request that does not open a session. */
    public static final String NO_SESSION = "NO_SESSION";
    /** A handshake carries a keyring and a root: far more than this is not one, and is not read. */
    public static final int MAX_BODY_BYTES = 256 * 1024;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HttpSessions() {
    }

    /**
     * A partner's answer to one {@code POST} to {@link #PATH}, with no web framework. The peer is the certificate's
     * issuer and the service it names, which the transport authenticated, never a name the body gives, so a client
     * cannot open a session as someone else; a request with no client certificate, or with one that names no single
     * service or no issuer, has no peer and opens nothing, and its body is not read. A body that is not a readable
     * request, or is over {@link #MAX_BODY_BYTES}, is {@code 400 INVALID_PARAMS}, and a readable one that cannot
     * open a session is {@code 400 NO_SESSION}; either way no session is opened, and none the peer holds is touched.
     * Otherwise it is {@code 200} with the signed reply.
     *
     * @param body the request body; read up to one byte past the limit, and not closed
     * @param peer the client certificate the transport authenticated, or null without one
     * @throws IOException when the body cannot be read
     */
    public static HttpAnswer serve(InputStream body, PeerCert peer, PartnerSessions sessions) throws IOException {
        if (peer == null || peer.peer().svc().isEmpty() || peer.issuer().isEmpty()) {
            return refusal(NO_SESSION);
        }
        SessionRequest req;
        try {
            byte[] bytes = body.readNBytes(MAX_BODY_BYTES + 1);
            if (bytes.length > MAX_BODY_BYTES) {
                return refusal(INVALID_PARAMS);
            }
            req = SessionRequest.parse(bytes);
        } catch (IllegalArgumentException e) {
            return refusal(INVALID_PARAMS);
        }
        if (!Sessions.opensSession(req)) {
            return refusal(NO_SESSION);
        }
        SessionReply reply;
        try {
            reply = sessions.open(req, peer.issuer(), peer.peer().svc());
        } catch (IllegalArgumentException e) {
            // Not reachable after the checks above, short of a repeated server nonce; refused, never a 500.
            return refusal(NO_SESSION);
        }
        return new HttpAnswer(200, reply.toJson().getBytes(StandardCharsets.UTF_8));
    }

    private static HttpAnswer refusal(String code) {
        return new HttpAnswer(400, error(code));
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
