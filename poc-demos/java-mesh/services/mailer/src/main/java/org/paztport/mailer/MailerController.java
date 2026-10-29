// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.mailer;

import java.util.Map;
import org.paztport.core.verify.ReasonCode;
import org.paztport.spring.PublicWrites;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sends email. An email leaves the shop for whoever reads the address, so it is a public write: the owner-aware
 * rule decides it, over the influence the request carries, with the address's owner taken from the mailer's own
 * directory and never from the request. Nothing is really sent; a sent email is one log line.
 */
@RestController
public class MailerController {

    private static final Logger LOG = LoggerFactory.getLogger(MailerController.class);

    /** An email: where it goes, and what it says. */
    public record Mail(String to, String subject, String body) {
    }

    private final Recipients recipients;
    private final PublicWrites writes;

    public MailerController(Recipients recipients, PublicWrites writes) {
        this.recipients = recipients;
        this.writes = writes;
    }

    @PostMapping("/send")
    public ResponseEntity<Map<String, String>> send(@RequestBody Mail mail) {
        if (writes.decide(recipients.ownerOf(mail.to())) != ReasonCode.OK) {
            return ResponseEntity.status(403).body(Map.of("reason", ReasonCode.INFLUENCE_DENIED.name()));
        }
        // The address and subject come from the request, so they are logged through LogSafe.
        LOG.info("MAIL to={} subject={}", LogSafe.of(mail.to()), LogSafe.of(mail.subject()));
        return ResponseEntity.ok(Map.of("status", "SENT"));
    }
}
