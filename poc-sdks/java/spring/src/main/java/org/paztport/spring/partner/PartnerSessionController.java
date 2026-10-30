// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.partner;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import org.paztport.http.HttpAnswer;
import org.paztport.http.HttpSessions;
import org.paztport.http.PartnerSessions;
import org.paztport.spring.internal.PeerIdentity;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The partner's {@code POST /paztport/session}: the Spring adapter over {@link HttpSessions#serve}, which says what
 * each answer is. The peer is the client certificate the TLS layer authenticated ({@link PeerIdentity}), never a name
 * the body gives, so a client cannot open a session as someone else. The answer is written as the SDK made it,
 * labelled JSON and nothing more.
 */
@RestController
class PartnerSessionController {

    private final PartnerSessions sessions;

    PartnerSessionController(PartnerSessions sessions) {
        this.sessions = sessions;
    }

    @PostMapping(HttpSessions.PATH)
    ResponseEntity<byte[]> open(HttpServletRequest request) throws IOException {
        HttpAnswer answer;
        try (InputStream in = request.getInputStream()) {
            answer = HttpSessions.serve(in, PeerIdentity.cert(request), sessions);
        }
        return ResponseEntity.status(answer.status()).contentType(MediaType.APPLICATION_JSON).body(answer.json());
    }
}
