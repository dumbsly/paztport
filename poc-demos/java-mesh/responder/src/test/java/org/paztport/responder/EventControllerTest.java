// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.event.EventEnvelope;
import org.paztport.core.event.EventVerifier;
import org.paztport.core.event.ResponderEvent;
import org.paztport.core.policy.Keyring;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class EventControllerTest {

    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final List<String> quarantined = new ArrayList<>();
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new EventController(
            new ResponderService(
                    new QuarantineDecider(new QuarantineConfig(1, 60_000, 2, 600_000), System::currentTimeMillis),
                    (svc, inst) -> quarantined.add(inst), Runnable::run),
            new EventVerifier(Keyring.of(Map.of("payment", payment.getPublic())),
                    Set.of("payment"), System::currentTimeMillis))).build();

    @Test
    void unsignedEventIsForbiddenAndTakesNoDecision() throws Exception {
        String plain = "{\"reason\":\"PATH_NOT_ALLOWED\",\"suspectSvc\":\"search\",\"suspectInst\":\"s1\","
                + "\"rid\":\"r\",\"audit\":false}";
        mvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON).content(plain))
                .andExpect(status().isForbidden());
        mvc.perform(post("/events")).andExpect(status().isForbidden());
        assertEquals(List.of(), quarantined);
    }

    @Test
    void signedEventIsDecided() throws Exception {
        String json = new ResponderEvent("PATH_NOT_ALLOWED", "search", "s1", "r", false, System.currentTimeMillis(),
                "e1").toJson();
        String body = EventEnvelope.sign("payment", json.getBytes(StandardCharsets.UTF_8), payment.getPrivate())
                .toJson();
        mvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("QUARANTINE"));
        assertEquals(List.of("s1"), quarantined);
    }

    /**
     * An event the payment key signed but with no {@code reason} once reached the decider as a null reason, and
     * its deny-list lookup threw. The verifier now refuses it as malformed, so it is a 403 that decides nothing.
     */
    @Test
    void aSignedEventWithNoReasonIsRefusedBeforeTheDecider() throws Exception {
        String json = "{\"audit\":false,\"eventId\":\"e2\",\"rid\":\"r\",\"suspectInst\":\"s1\","
                + "\"suspectSvc\":\"search\",\"ts\":" + System.currentTimeMillis() + "}";
        String body = EventEnvelope.sign("payment", json.getBytes(StandardCharsets.UTF_8), payment.getPrivate())
                .toJson();
        mvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("event refused"));
        assertEquals(List.of(), quarantined);
    }

    @Test
    void aDisallowedSignerCannotWriteItsOwnLogLines() throws Exception {
        String forged = "{\"payload\":\"e30\",\"sig\":\"AAAA\",\"signer\":\"x\\nESCALATE svc=search inst=s1\"}";
        List<String> lines;
        try (LogCapture capture = new LogCapture(EventController.class)) {
            mvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON).content(forged))
                    .andExpect(status().isForbidden());
            lines = capture.lines();
        }
        assertEquals(1, lines.size());
        assertFalse(lines.get(0).contains("\n"), lines.get(0));
        assertFalse(lines.get(0).contains("ESCALATE"), lines.get(0));
        assertEquals("refused event: signer not allowed", lines.get(0));
    }
}
