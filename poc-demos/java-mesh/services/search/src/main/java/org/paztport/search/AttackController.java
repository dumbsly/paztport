// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.PathChain;
import org.paztport.core.RequestBinding;
import org.paztport.core.Stamp;
import org.paztport.core.StampSigner;
import org.paztport.spring.PathAttestContext;
import org.paztport.spring.PathAttestHeaders;
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

    private final RestClient stampedClient;          // normal client: the interceptor stamps as search
    private final RestClient rawClient = RestClient.create(); // no interceptor: full header control
    private final ObjectMapper json = new ObjectMapper();
    private final StolenChainStore stolenChains;
    private final String paymentUrl;
    private final PrivateKey searchKey;
    private final String inst;

    public AttackController(
            RestClient stampedClient,
            StolenChainStore stolenChains,
            @Value("${downstream.payment-url}") String paymentUrl,
            @Value("${path-attest.key-path}") String keyPath) throws Exception {
        this.stampedClient = stampedClient;
        this.stolenChains = stolenChains;
        this.paymentUrl = paymentUrl;
        this.searchKey = Crypto.decodePrivateKey(Base64Url.decode(Files.readString(Path.of(keyPath)).trim()));
        String host = System.getenv("HOSTNAME");
        this.inst = host != null && !host.isBlank() ? host : "search-attacker";
    }

    /** Scenario 2: call payment with no path headers at all. */
    @PostMapping("/attack/no-headers")
    public ResponseEntity<String> noHeaders() {
        return callPayment(rawClient, null, null, BODY);
    }

    /** Scenario 3: forge a stamp claiming svc gateway, signed with search's own key. */
    @PostMapping("/attack/forge-gateway")
    public ResponseEntity<String> forgeGateway() {
        String bind = RequestBinding.compute("POST", "/pay", BODY);
        Stamp forged = StampSigner.sign(
                "gateway", inst, UUID.randomUUID().toString(), System.currentTimeMillis(), bind, "", searchKey);
        String chain = new PathChain(List.of(forged)).encode();
        return callPayment(rawClient, chain, null, BODY);
    }

    /** Scenario 4 / 10: forward a real gateway->search chain on to payment. */
    @PostMapping("/attack/forward-stolen")
    public ResponseEntity<String> forwardStolen() {
        PathChain stolen = stolenChains.last();
        if (stolen == null) {
            return ResponseEntity.status(428)
                    .body("{\"reason\":\"NO_STOLEN_CHAIN\",\"hint\":\"call gateway /find first\"}");
        }
        // Let the normal interceptor append search's own stamp to the stolen chain.
        PathAttestContext.setInboundChain(stolen);
        try {
            return callPayment(stampedClient, null, null, BODY);
        } finally {
            PathAttestContext.clear();
        }
    }

    /** Scenario 5 / 7: replay a captured valid request verbatim (fresh -> REPLAY, aged -> EXPIRED). */
    @PostMapping("/attack/replay")
    public ResponseEntity<String> replay() {
        CapturedView c = fetchCaptured();
        if (c == null) {
            return ResponseEntity.status(428).body("{\"reason\":\"NO_CAPTURE\",\"hint\":\"run a checkout first\"}");
        }
        return callPayment(rawClient, c.chain(), c.proof(), Base64.getDecoder().decode(c.bodyBase64()));
    }

    /** Scenario 6: replay a captured valid request with the body altered. */
    @PostMapping("/attack/alter-body")
    public ResponseEntity<String> alterBody() {
        CapturedView c = fetchCaptured();
        if (c == null) {
            return ResponseEntity.status(428).body("{\"reason\":\"NO_CAPTURE\",\"hint\":\"run a checkout first\"}");
        }
        return callPayment(rawClient, c.chain(), c.proof(), "{\"amount\":999999}".getBytes(StandardCharsets.UTF_8));
    }

    private CapturedView fetchCaptured() {
        return rawClient.get()
                .uri(paymentUrl + "/debug/last-request")
                .exchange((request, response) -> response.getStatusCode().is2xxSuccessful()
                        ? json.readValue(response.getBody(), CapturedView.class)
                        : null, false);
    }

    private record CapturedView(String chain, String proof, String method, String path, String bodyBase64) {
    }

    private ResponseEntity<String> callPayment(RestClient client, String chain, String proof, byte[] body) {
        return client.post()
                .uri(paymentUrl + "/pay")
                .headers(h -> {
                    h.setContentType(MediaType.APPLICATION_JSON);
                    if (chain != null) {
                        h.set(PathAttestHeaders.CHAIN, chain);
                    }
                    if (proof != null) {
                        h.set(PathAttestHeaders.PROOF, proof);
                    }
                })
                .body(body)
                .exchange((request, response) -> ResponseEntity
                        .status(response.getStatusCode())
                        .body(new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)), false);
    }
}
