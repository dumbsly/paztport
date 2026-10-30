// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.tickets;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.StampV3;
import org.paztport.http.RequestContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Takes a customer's support ticket and hands it to the assistant. The ticket's text is written by someone outside
 * the shop, so before anything reads it, it is added to the request's influence as {@code third-party}, named by
 * the ticket and committed to by its hash. Every call the assistant makes from it then carries that, and a service
 * asked to write somewhere public can see the request was shaped by text nobody vouched for.
 *
 * <p>The answer names the request's {@code rid}, the one every hop's trace line carries, so the demo can follow
 * the ticket through the mesh and across the boundary. The assistant's actions are read into a tree of the SDK's
 * own Jackson, so the answer is written with that Jackson too and handed to the web layer as a string: the web
 * layer's Jackson is another major version, and would write that tree as a bean, not as the JSON it holds.
 */
@RestController
public class TicketsController {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** A ticket as the gateway sends it: the customer its token named, and what they wrote. */
    public record Ticket(String author, String text) {
    }

    private final RestClient http;
    private final String assistantUrl;
    private final AtomicLong sequence = new AtomicLong();

    public TicketsController(RestClient http, @Value("${downstream.assistant-url}") String assistantUrl) {
        this.http = http;
        this.assistantUrl = assistantUrl;
    }

    @PostMapping("/tickets")
    public ResponseEntity<?> ticket(@RequestBody Ticket ticket) {
        String id = "t-" + sequence.incrementAndGet();
        String text = ticket.text() == null ? "" : ticket.text();
        String hash = Base64Url.encode(Crypto.sha256(text.getBytes(StandardCharsets.UTF_8)));
        RequestContext.addInfluence(new InfluenceEntry(InfluenceClass.THIRD_PARTY, "ticket:" + id, hash, null, null));

        Map<String, String> assist = new LinkedHashMap<>();
        assist.put("ticket", id);
        assist.put("author", ticket.author());
        assist.put("text", text);
        // exchange applies no status handlers, so a refusal downstream is relayed rather than thrown.
        return http.post()
                .uri(assistantUrl + "/assist")
                .contentType(MediaType.APPLICATION_JSON)
                .body(assist)
                .exchange((request, response) -> {
                    byte[] body = response.getBody().readAllBytes();
                    if (!response.getStatusCode().is2xxSuccessful()) {
                        return ResponseEntity.status(response.getStatusCode())
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(body);
                    }
                    Map<String, Object> answer = new LinkedHashMap<>();
                    answer.put("ticket", id);
                    answer.put("author", ticket.author());
                    answer.put("rid", rid());
                    answer.put("actions", actions(body));
                    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                            .body(JSON.writeValueAsString(answer));
                });
    }

    /** The request's rid, from the chain the gateway started; null only outside a verified request. */
    private static String rid() {
        List<StampV3> chain = RequestContext.inboundChain();
        return chain == null || chain.isEmpty() ? null : chain.get(0).rid();
    }

    private static JsonNode actions(byte[] body) throws IOException {
        return JSON.readTree(body).path("actions");
    }
}
