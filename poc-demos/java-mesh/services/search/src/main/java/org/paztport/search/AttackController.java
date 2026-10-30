// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.stamp.StampV3;
import org.paztport.http.HttpV3;
import org.paztport.http.PaztportHeaders;
import org.paztport.http.RequestBinding;
import org.paztport.http.RequestContext;
import org.paztport.spring.outbound.PooledTlsClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Attacker behaviours, enabled only when {@code attack.enabled=true}. Each
 * endpoint drives one illicit call at payment and mirrors payment's status and
 * body back to the caller so the demo can assert the verdict. Normal /search
 * traffic is unaffected.
 */
@RestController
@ConditionalOnProperty(name = "attack.enabled", havingValue = "true")
public class AttackController {

    private static final byte[] BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);

    private final RestClient stampedClient; // normal client: the interceptor stamps as search
    private final RestClient rawClient;     // no interceptor, so full header control; still search's certificate
    private final ObjectMapper json = new ObjectMapper();
    private final StolenChainStore stolenChains;
    private final String paymentUrl;
    private final PrivateKey searchKey;
    private final String inst;

    public AttackController(
            RestClient stampedClient,
            StolenChainStore stolenChains,
            @Value("${downstream.payment-url}") String paymentUrl,
            @Value("${paztport.key-path}") String keyPath,
            PooledTlsClient tls) throws Exception {
        this.stampedClient = stampedClient;
        // Built apart from the shared builder, so it never gets the stamping interceptor, but on the starter's
        // pooled client, so it reuses connections like every other call. Payment requires a client certificate,
        // and the attacker can only present its own: every attack arrives as search.
        this.rawClient = tls.builder().build();
        this.stolenChains = stolenChains;
        this.paymentUrl = paymentUrl;
        this.searchKey = KeyFiles.loadPrivateKey(Path.of(keyPath));
        String host = System.getenv("HOSTNAME");
        this.inst = host != null && !host.isBlank() ? host : "search-attacker";
    }

    /** Scenario 2: call payment with no path headers at all. */
    @PostMapping("/attack/no-headers")
    public ResponseEntity<String> noHeaders() {
        return callPayment(rawClient, null, null, null, BODY);
    }

    /** Scenario 3: forge a stamp claiming svc gateway, signed with search's own key. */
    @PostMapping("/attack/forge-gateway")
    public ResponseEntity<String> forgeGateway() {
        String bind = RequestBinding.compute("POST", "/pay", BODY);
        StampV3 forged = StampV3.sign("gateway", inst, UUID.randomUUID().toString(), System.currentTimeMillis(), "",
                "payment", bind, "", "", searchKey);
        String chain = HttpV3.encodeChain(List.of(forged));
        return callPayment(rawClient, chain, null, null, BODY);
    }

    /** Scenario 4 / 10: forward a real gateway->search chain on to payment. */
    @PostMapping("/attack/forward-stolen")
    public ResponseEntity<String> forwardStolen() {
        List<StampV3> stolen = stolenChains.last();
        if (stolen == null) {
            return ResponseEntity.status(428)
                    .body("{\"reason\":\"NO_STOLEN_CHAIN\",\"hint\":\"call gateway /find first\"}");
        }
        // Let the normal interceptor append search's own stamp to the stolen chain. The rest of the context
        // belongs to the filter serving this request, so only the chain is swapped, and it is put back after.
        List<StampV3> previous = RequestContext.inboundChain();
        RequestContext.setInboundChain(stolen);
        try {
            return callPayment(stampedClient, null, null, null, BODY);
        } finally {
            RequestContext.setInboundChain(previous);
        }
    }

    /** Scenario 5 / 7: replay a captured valid request verbatim (fresh -> REPLAY, aged -> EXPIRED). */
    @PostMapping("/attack/replay")
    public ResponseEntity<String> replay() {
        CapturedView c = fetchCaptured();
        if (c == null) {
            return ResponseEntity.status(428).body("{\"reason\":\"NO_CAPTURE\",\"hint\":\"run a checkout first\"}");
        }
        return callPayment(rawClient, c.chain(), c.proof(), c.influence(), Base64.getDecoder().decode(c.bodyBase64()));
    }

    /** Scenario 6: replay a captured valid request with the body altered. */
    @PostMapping("/attack/alter-body")
    public ResponseEntity<String> alterBody() {
        CapturedView c = fetchCaptured();
        if (c == null) {
            return ResponseEntity.status(428).body("{\"reason\":\"NO_CAPTURE\",\"hint\":\"run a checkout first\"}");
        }
        return callPayment(rawClient, c.chain(), c.proof(), c.influence(),
                "{\"amount\":999999}".getBytes(StandardCharsets.UTF_8));
    }

    /** The exchange closes the response, read or not, so an unread refusal does not hold a pooled connection. */
    private CapturedView fetchCaptured() {
        return rawClient.get()
                .uri(paymentUrl + "/debug/last-request")
                .exchange((request, response) -> response.getStatusCode().is2xxSuccessful()
                        ? json.readValue(response.getBody(), CapturedView.class)
                        : null);
    }

    private record CapturedView(
            String chain, String proof, String influence, String method, String path, String bodyBase64) {
    }

    private ResponseEntity<String> callPayment(
            RestClient client, String chain, String proof, String influence, byte[] body) {
        return client.post()
                .uri(paymentUrl + "/pay")
                .headers(h -> {
                    h.setContentType(MediaType.APPLICATION_JSON);
                    if (chain != null) {
                        h.set(PaztportHeaders.CHAIN, chain);
                    }
                    if (proof != null) {
                        h.set(PaztportHeaders.PROOF, proof);
                    }
                    if (influence != null) {
                        h.set(PaztportHeaders.INFLUENCE, influence);
                    }
                })
                .body(body)
                .exchange((request, response) -> ResponseEntity
                        .status(response.getStatusCode())
                        .body(new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }
}
