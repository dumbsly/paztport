// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.assistant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * The support assistant. <strong>There is no model here.</strong> This is a scripted stand-in for a model whose
 * ticket has hijacked it: {@link Script} reads the ticket's text with a few patterns and the assistant does what
 * the text asks, whoever wrote it. It reads orders, asks payment for a refund (which payment takes on to the PSP,
 * across the boundary), and asks the mailer to send an email. It checks nothing itself, as a hijacked model would
 * not, so that what keeps a malicious ticket in bounds is visibly elsewhere: the mailer and the PSP judge each
 * write by the influence the request carries, which the assistant's calls commit to without its help.
 *
 * <p>It calls each of orders, payment and the mailer at most once per ticket: one read, one refund, one email.
 * That is not a choice of style. Each receiver remembers the nonce of each request it has seen from a sender, keyed
 * by the request's {@code rid} and that sender, so a second call to the same receiver within one ticket would be
 * refused as a replay.
 *
 * <p>No call throws on a refusal: every reply, whatever its status, becomes one {@link Action} in the answer.
 */
@RestController
public class AssistantController {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** A ticket as tickets sends it: its id, the customer who wrote it, and the text. */
    public record Assist(String ticket, String author, String text) {
    }

    private final RestClient http;
    private final String ordersUrl;
    private final String paymentUrl;
    private final String mailerUrl;

    public AssistantController(RestClient http,
            @Value("${downstream.orders-url}") String ordersUrl,
            @Value("${downstream.payment-url}") String paymentUrl,
            @Value("${downstream.mailer-url}") String mailerUrl) {
        this.http = http;
        this.ordersUrl = ordersUrl;
        this.paymentUrl = paymentUrl;
        this.mailerUrl = mailerUrl;
    }

    @PostMapping("/assist")
    public Map<String, List<Action>> assist(@RequestBody Assist assist) {
        Script.Plan plan = Script.plan(assist.text());
        List<Action> actions = new ArrayList<>();

        // 1. Read: someone's order history, or the one order. What orders answers is labelled with its owner.
        Reply read = null;
        if (plan.historyEmail() != null) {
            read = get(URI.create(ordersUrl + "/orders?email="
                    + URLEncoder.encode(plan.historyEmail(), StandardCharsets.UTF_8)));
        } else if (plan.order() != null) {
            read = get(URI.create(ordersUrl + "/orders/" + plan.order()));
        }
        if (read != null) {
            actions.add(read.action("read-orders"));
        }

        // 2. Refund: to the card the ticket names, or, for a damaged order, to the card that paid.
        Reply refund = null;
        if (plan.order() != null && (plan.refundCard() != null || plan.damaged())) {
            Map<String, String> body = new LinkedHashMap<>();
            body.put("order", plan.order());
            if (plan.refundCard() != null) {
                body.put("card", plan.refundCard());
            }
            refund = post(paymentUrl + "/refund", body);
            actions.add(refund.action("refund"));
        }

        // 3. Email: what was read, to wherever the ticket says; else word of the refund, to the order's address.
        Map<String, String> mail = null;
        if (plan.emailTo() != null) {
            mail = mail(plan.emailTo(), "Order history", read == null ? "" : read.text());
        } else if (refund != null) {
            String to = read == null ? null : emailOf(read.json(), plan.order());
            if (to != null) {
                mail = mail(to, "Refund for order " + plan.order(),
                        "Your refund for order " + plan.order() + ": " + refund.result() + ".");
            }
        }
        if (mail != null) {
            actions.add(post(mailerUrl + "/send", mail).action("email"));
        }
        return Map.of("actions", actions);
    }

    private static Map<String, String> mail(String to, String subject, String body) {
        Map<String, String> mail = new LinkedHashMap<>();
        mail.put("to", to);
        mail.put("subject", subject);
        mail.put("body", body);
        return mail;
    }

    /** The address on the order read: the order itself, or the one with this id in a history. */
    private static String emailOf(JsonNode read, String order) {
        if (read == null) {
            return null;
        }
        if (read.path("email").isTextual()) {
            return read.path("email").asText();
        }
        for (JsonNode o : read.path("orders")) {
            if (order.equals(o.path("id").asText()) && o.path("email").isTextual()) {
                return o.path("email").asText();
            }
        }
        return null;
    }

    // exchange applies no status handlers, so a refusal comes back as a reply rather than an exception.
    private Reply get(URI uri) {
        return http.get().uri(uri)
                .exchange((request, response) ->
                        new Reply(response.getStatusCode().value(), response.getBody().readAllBytes()));
    }

    private Reply post(String url, Map<String, String> body) {
        return http.post().uri(url)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .exchange((request, response) ->
                        new Reply(response.getStatusCode().value(), response.getBody().readAllBytes()));
    }

    /** A reply as it came back: its status and its body. */
    private record Reply(int status, byte[] body) {

        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }

        /** The body as JSON, or null when it is not. */
        JsonNode json() {
            try {
                return JSON.readTree(body);
            } catch (IOException e) {
                return null;
            }
        }

        /** The reply's {@code reason}, else its {@code status}, else {@code ok}. */
        String result() {
            JsonNode json = json();
            if (json != null && json.path("reason").isTextual()) {
                return json.path("reason").asText();
            }
            if (json != null && json.path("status").isTextual()) {
                return json.path("status").asText();
            }
            return "ok";
        }

        Action action(String name) {
            return new Action(name, status, result());
        }
    }
}
