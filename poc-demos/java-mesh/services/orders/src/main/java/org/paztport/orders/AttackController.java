// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.wire.HttpWire;
import org.paztport.http.wire.PaztportHeaders;
import org.paztport.http.wire.RequestBinding;
import org.paztport.spring.outbound.PooledTlsClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Code running in orders that misuses its calls to payment, enabled only when {@code attack.enabled=true}. It holds
 * what orders holds, its stamp key and its proofs, and signs as orders. Each endpoint steers one call at payment and
 * mirrors payment's status and body back to the caller so the demo can assert the verdict. The honest endpoints are
 * unaffected.
 */
@RestController
@ConditionalOnProperty(name = "attack.enabled", havingValue = "true")
public class AttackController {

    private static final byte[] PAY_BODY = "{\"amount\":100}".getBytes(StandardCharsets.UTF_8);
    // The body orders sends payment on alice's purchase of order 123.
    private static final byte[] CHARGE_BODY =
            "{\"customer\":\"alice\",\"order\":\"123\",\"card\":\"4242 4242 4242 4242\",\"amount\":100}"
                    .getBytes(StandardCharsets.UTF_8);
    // The proof the attacker attaches: of the one route on which orders may call payment's pay.
    private static final String CREATE_ORDER_PAY = Routes.join(List.of("gateway", "orders#createOrder", "payment#pay"));
    // The proof of the one route on which orders may call payment's hold.
    private static final String HOLD_ITEMS_HOLD = Routes.join(List.of("gateway", "orders#holdItems", "payment#hold"));

    private final RestClient rawClient; // no interceptor, so full header control; still orders' certificate
    private final Stamper stamper;
    private final ProofBundle proofs;
    private final StolenChainStore stolenChains;
    private final String paymentUrl;

    public AttackController(
            Stamper stamper,
            ProofBundle proofs,
            StolenChainStore stolenChains,
            @Value("${downstream.payment-url}") String paymentUrl,
            PooledTlsClient tls) {
        // Built apart from the shared builder, so it never gets the stamping interceptor, but on the starter's
        // pooled client: payment requires a client certificate, and every steered call arrives as orders.
        this.rawClient = tls.builder().build();
        this.stamper = stamper;
        this.proofs = proofs;
        this.stolenChains = stolenChains;
        this.paymentUrl = paymentUrl;
    }

    /**
     * Scenario 15a: in through {@code getOrder}, which never calls payment, the code signs a call to payment's
     * {@code pay} onto that chain. The chain's route is {@code gateway/orders#getOrder/payment#pay}, which no proof
     * proves, so it attaches the proof of {@code createOrder}'s call to {@code pay}, the best it holds.
     */
    @PostMapping("/attack/steer-pay")
    public ResponseEntity<String> steerPay() {
        List<Stamp> stolen = stolenChains.getOrder();
        if (stolen == null) {
            return ResponseEntity.status(428)
                    .body("{\"reason\":\"NO_STOLEN_CHAIN\",\"hint\":\"call gateway GET /orders/123 first\"}");
        }
        return steer(stolen, "payment#pay", "/pay", PAY_BODY, CREATE_ORDER_PAY);
    }

    /**
     * Scenario 15b: in through {@code createOrder}, the code names {@code payment#pay}, the operation that route
     * allows, but sends the call to {@code /charge}. The stamp binds the {@code /charge} request it goes with, and the
     * proof is the route's own; payment refuses it on the operation it dispatches, before its replay check, which
     * would otherwise stop this second call from orders in the request tree.
     */
    @PostMapping("/attack/misname")
    public ResponseEntity<String> misname() {
        List<Stamp> stolen = stolenChains.createOrder();
        if (stolen == null) {
            return ResponseEntity.status(428)
                    .body("{\"reason\":\"NO_STOLEN_CHAIN\",\"hint\":\"call gateway POST /checkout first\"}");
        }
        return steer(stolen, "payment#pay", "/charge", CHARGE_BODY, CREATE_ORDER_PAY);
    }

    /**
     * Scenario 16c: in through {@code holdItems}, the code names {@code payment#hold} and sends the call to
     * {@code /holds/%41}, the item {@code A} with its letter percent-encoded. The stamp binds that request and the
     * proof is the route's own, but the key value of a keyed operation must be spelt out in the path: payment finds
     * none here and refuses the call, so an encoded segment is no way round the once-per-item key.
     */
    @PostMapping("/attack/encoded-hold")
    public ResponseEntity<String> encodedHold() {
        List<Stamp> stolen = stolenChains.holdItems();
        if (stolen == null) {
            return ResponseEntity.status(428)
                    .body("{\"reason\":\"NO_STOLEN_CHAIN\",\"hint\":\"call gateway POST /holds first\"}");
        }
        return steer(stolen, "payment#hold", "/holds/%41", new byte[0], HOLD_ITEMS_HOLD);
    }

    /**
     * Signs a stamp for {@code operation} of payment onto {@code stolen}, binding a POST of {@code body} to
     * {@code path}, and sends it there with the proof of {@code route}. Without that proof it sends nothing, so a
     * refusal is never for a proof the bundle lacked.
     */
    private ResponseEntity<String> steer(List<Stamp> stolen, String operation, String path, byte[] body,
            String route) {
        MerkleProof proof = proofs.proofFor(route);
        if (proof == null) {
            return ResponseEntity.status(409).body("{\"reason\":\"NO_PROOF\",\"route\":\"" + route + "\"}");
        }
        String bind = RequestBinding.compute("POST", path, body);
        List<Stamp> chain = stamper.next(stolen, operation, bind, List.of(), null).chain();
        return rawClient.post()
                .uri(paymentUrl + path)
                .headers(h -> {
                    h.setContentType(MediaType.APPLICATION_JSON);
                    h.set(PaztportHeaders.CHAIN, HttpWire.encodeChain(chain));
                    h.set(PaztportHeaders.PROOF, HttpWire.encodeProof(proof));
                })
                .body(body)
                .exchange((request, response) -> ResponseEntity
                        .status(response.getStatusCode())
                        .body(new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }
}
