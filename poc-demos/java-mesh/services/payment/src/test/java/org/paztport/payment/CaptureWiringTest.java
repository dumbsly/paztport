// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

// The SDK filter hands each received request to the demo's listener, and the
// debug endpoint (skipped by the filter) serves the last one back for replay.
// The TLS client is off too: it reads its certificates at startup, and none are mounted here.
@SpringBootTest(properties = {"paztport.verify=false", "paztport.capture=true", "paztport.tls-bundle=false"})
@AutoConfigureMockMvc
class CaptureWiringTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void theLastReceivedRequestIsServedForReplay() throws Exception {
        mvc.perform(get("/debug/last-request")).andExpect(status().isNotFound());

        mvc.perform(post("/pay").header("X-Path-Chain", "chain-1").header("X-Path-Proof", "proof-1")
                .contentType(MediaType.APPLICATION_JSON).content("{\"amount\":100}"))
                .andExpect(status().isOk());

        mvc.perform(get("/debug/last-request"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.chain").value("chain-1"))
                .andExpect(jsonPath("$.proof").value("proof-1"))
                .andExpect(jsonPath("$.method").value("POST"))
                .andExpect(jsonPath("$.path").value("/pay"))
                .andExpect(jsonPath("$.bodyBase64").value("eyJhbW91bnQiOjEwMH0="));
    }
}
