// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.Crypto;
import org.paztport.core.EventEnvelope;
import org.paztport.core.Keyring;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EventControllerTest {

    private final KeyPair payment = Crypto.generateEd25519KeyPair();
    private final List<String> quarantined = new ArrayList<>();
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new EventController(
            new ResponderService(
                    new QuarantineDecider(new QuarantineConfig(1, 60_000, 2, 600_000), System::currentTimeMillis),
                    (svc, inst) -> quarantined.add(inst), Runnable::run),
            new EventAuthenticator(Keyring.of(Map.of("payment", payment.getPublic())),
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
        String json = "{\"reason\":\"PATH_NOT_ALLOWED\",\"suspectSvc\":\"search\",\"suspectInst\":\"s1\","
                + "\"rid\":\"r\",\"audit\":false,\"ts\":" + System.currentTimeMillis() + ",\"eventId\":\"e1\"}";
        String body = new ObjectMapper().writeValueAsString(
                EventEnvelope.sign("payment", json.getBytes(StandardCharsets.UTF_8), payment.getPrivate()));
        mvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("QUARANTINE"));
        assertEquals(List.of("s1"), quarantined);
    }
}
