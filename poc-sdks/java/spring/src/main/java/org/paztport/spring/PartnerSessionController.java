// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import org.paztport.core.Peer;
import org.paztport.core.SessionRequest;
import org.paztport.core.Sessions;
import org.paztport.http.HttpSessions;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The partner's {@code POST /paztport/session}. The peer is the service the TLS layer authenticated, never a name
 * the body gives, so a client cannot open a session as someone else; a request with no client certificate, or with
 * one that names no single service, has no peer and opens nothing. A body that is not a readable request is
 * {@code INVALID_PARAMS}, and a readable one that cannot open a session is {@code NO_SESSION}; either way the
 * peer's current session stays as it was.
 */
@RestController
class PartnerSessionController {

    /** A handshake carries a keyring and a root: far more than this is not one, and is not read. */
    private static final int MAX_BODY_BYTES = 256 * 1024;

    private final PartnerSessions sessions;

    PartnerSessionController(PartnerSessions sessions) {
        this.sessions = sessions;
    }

    @PostMapping(HttpSessions.PATH)
    ResponseEntity<?> open(HttpServletRequest request) throws IOException {
        Peer peer = PeerIdentity.from(request);
        if (peer == null || peer.svc().isEmpty()) {
            return error(HttpSessions.NO_SESSION);
        }
        SessionRequest req;
        try (InputStream in = request.getInputStream()) {
            byte[] body = in.readNBytes(MAX_BODY_BYTES + 1);
            if (body.length > MAX_BODY_BYTES) {
                return error(HttpSessions.INVALID_PARAMS);
            }
            req = HttpSessions.parseRequest(body);
        } catch (IllegalArgumentException e) {
            return error(HttpSessions.INVALID_PARAMS);
        }
        if (!Sessions.opensSession(req)) {
            return error(HttpSessions.NO_SESSION);
        }
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(sessions.open(req, peer.svc()).toJson().toString());
    }

    private static ResponseEntity<byte[]> error(String code) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON)
                .body(HttpSessions.error(code));
    }
}
