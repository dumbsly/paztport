// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.ServletException;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.boundary.RequirementUnmetException;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

// Payment requires influence of the PSP, so the egress withholds a call when the PSP's session does not give it.
// Only the egress makes that refusal (its constructor is the SDK's), so the client here is a mock that throws it.
class PartnerControllerTest {

    private final BoundaryClient client = mock(BoundaryClient.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PartnerController(
            new StaticListableBeanFactory(Map.of("client", client)).getBeanProvider(BoundaryClient.class))).build();

    private static MockHttpServletRequestBuilder charge() {
        return post("/charge").contentType(MediaType.APPLICATION_JSON).content("{\"order\":\"123\"}");
    }

    @Test
    void aCallTheEgressWithholdsIs502ExtensionRequired() throws Exception {
        when(client.post(eq("/charge"), any())).thenThrow(RequirementUnmetException.class);

        mvc.perform(charge())
                .andExpect(status().isBadGateway())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().string("{\"reason\":\"EXTENSION_REQUIRED\"}"));
    }

    // The egress's other refusals to send are IllegalStateExceptions too, and none of them is about the PSP's
    // extensions, so none is answered as one.
    @Test
    void anotherRefusalToSendIsNotAnsweredAsAMissingExtension() {
        when(client.post(eq("/charge"), any())).thenThrow(new IllegalStateException("no session could be opened"));

        ServletException thrown = assertThrows(ServletException.class, () -> mvc.perform(charge()));
        assertInstanceOf(IllegalStateException.class, thrown.getCause());
    }
}
