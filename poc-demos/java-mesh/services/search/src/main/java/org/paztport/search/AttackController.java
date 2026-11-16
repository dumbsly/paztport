// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.http.RequestContext;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.paztport.spring.outbound.PooledTlsClient;
import org.springframework.beans.factory.annotation.Autowired;
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

    /** The endpoints over search's stamping client and key, sending raw calls on the starter's pooled client. */
    @Autowired
    public AttackController(
            RestClient stampedClient,
            StolenChainStore stolenChains,
            @Value("${downstream.payment-url}") String paymentUrl,
            @Value("${paztport.key-path}") String keyPath,
            PooledTlsClient tls) throws Exception {
        // The raw client is built apart from the shared builder, so it never gets the stamping interceptor, but on
        // the starter's pooled client, so it reuses connections like every other call. Payment requires a client
        // certificate, and the attacker can only present its own: every attack arrives as search.
        this(stampedClient, tls.builder().build(), stolenChains, paymentUrl,
                KeyFiles.loadPrivateKey(Path.of(keyPath)), instance());
    }

    /** As the public constructor, with the raw client, search's key and its instance given; for tests. */
    AttackController(RestClient stampedClient, RestClient rawClient, StolenChainStore stolenChains, String paymentUrl,
            PrivateKey searchKey, String inst) {
        this.stampedClient = stampedClient;
        this.rawClient = rawClient;
        this.stolenChains = stolenChains;
        this.paymentUrl = paymentUrl;
        this.searchKey = searchKey;
        this.inst = inst;
    }

    private static String instance() {
        String host = System.getenv("HOSTNAME");
        return host != null && !host.isBlank() ? host : "search-attacker";
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
        Stamp forged = Stamp.sign("gateway", inst, UUID.randomUUID().toString(), System.currentTimeMillis(), "",
                "payment", bind, "", "", searchKey);
        String chain = HttpWire.encodeChain(List.of(forged));
        return callPayment(rawClient, chain, null, null, BODY);
    }

    /**
     * Scenario 4 / 8c / 9 / 10: forward a real gateway->search chain on to payment, with the blocks it came with, so
     * each still matches the stamp that committed to it (check 9a) and payment meets the chain at its route.
     */
    @PostMapping("/attack/forward-stolen")
    public ResponseEntity<String> forwardStolen() {
        StolenChainStore.Stolen stolen = stolenChains.last();
        if (stolen == null) {
            return noStolenChain();
        }
        return forward(stolen.chain(), stolen.blocks());
    }

    /**
     * Scenario 4b: forward a real gateway->search chain on to payment with one block altered: the gateway's gains an
     * influence entry it never signed, and every other block goes unchanged. The gateway's stamp no longer commits to
     * its block, which is check 9a's. The gateway's block holds no entry to strip, so one is added; any change to a
     * committed block is the same refusal.
     */
    @PostMapping("/attack/forward-altered")
    public ResponseEntity<String> forwardAltered() {
        StolenChainStore.Stolen stolen = stolenChains.last();
        if (stolen == null) {
            return noStolenChain();
        }
        List<Block> blocks = new ArrayList<>(stolen.blocks());
        blocks.set(0, withEntryAdded(blocks.get(0)));
        return forward(stolen.chain(), blocks);
    }

    /** {@code block} with one more influence entry, after any it holds; its other names and requires unchanged. */
    private static Block withEntryAdded(Block block) {
        Map<String, List<String>> items = new LinkedHashMap<>();
        for (String name : block.names()) {
            items.put(name, block.itemsUnder(name));
        }
        List<String> influence = new ArrayList<>(items.getOrDefault(Influence.NAME, List.of()));
        influence.add(new InfluenceEntry(InfluenceClass.PUBLIC, "search:attack",
                Base64Url.encode(Crypto.sha256(BODY)), null, null).toJson());
        items.put(Influence.NAME, influence);
        return Block.of(items, block.requires());
    }

    /**
     * Lets the normal interceptor append search's own stamp and block to {@code chain} and {@code blocks}, and calls
     * payment. The rest of the context belongs to the filter serving this request, so only the chain and its blocks
     * are swapped, and both are put back after.
     */
    private ResponseEntity<String> forward(List<Stamp> chain, List<Block> blocks) {
        List<Stamp> previous = RequestContext.inboundChain();
        List<Block> previousBlocks = RequestContext.inboundBlocks();
        RequestContext.setInboundChain(chain, blocks);
        try {
            return callPayment(stampedClient, null, null, null, BODY);
        } finally {
            if (previousBlocks != null) {
                RequestContext.setInboundChain(previous, previousBlocks);
            } else {
                RequestContext.setInboundChain(previous);
            }
        }
    }

    private static ResponseEntity<String> noStolenChain() {
        return ResponseEntity.status(428)
                .body("{\"reason\":\"NO_STOLEN_CHAIN\",\"hint\":\"call gateway /find first\"}");
    }

    /**
     * Scenario 5 / 7: replay a captured valid request verbatim. Fresh, it is PEER_MISMATCH: search is not the last
     * signer, and payment checks the peer before the nonce, so the nonce is not spent. Aged, it is EXPIRED, which
     * is checked first.
     */
    @PostMapping("/attack/replay")
    public ResponseEntity<String> replay() {
        CapturedView c = fetchCaptured();
        if (c == null) {
            return ResponseEntity.status(428).body("{\"reason\":\"NO_CAPTURE\",\"hint\":\"run a checkout first\"}");
        }
        return callPayment(rawClient, c.chain(), c.proof(), c.blocks(), Base64.getDecoder().decode(c.bodyBase64()));
    }

    /** Scenario 6: replay a captured valid request with the body altered. */
    @PostMapping("/attack/alter-body")
    public ResponseEntity<String> alterBody() {
        CapturedView c = fetchCaptured();
        if (c == null) {
            return ResponseEntity.status(428).body("{\"reason\":\"NO_CAPTURE\",\"hint\":\"run a checkout first\"}");
        }
        return callPayment(rawClient, c.chain(), c.proof(), c.blocks(),
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
            String chain, String proof, String blocks, String method, String path, String bodyBase64) {
    }

    private ResponseEntity<String> callPayment(
            RestClient client, String chain, String proof, String blocks, byte[] body) {
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
                    if (blocks != null) {
                        h.set(PaztportHeaders.EXTENSIONS, blocks);
                    }
                })
                .body(body)
                .exchange((request, response) -> ResponseEntity
                        .status(response.getStatusCode())
                        .body(new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }
}
