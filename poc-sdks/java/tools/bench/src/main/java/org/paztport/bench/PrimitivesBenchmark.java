// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.bench;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.Keyring;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.stamp.Stamper;
import org.paztport.http.wire.RequestBinding;

/**
 * The primitives a verifying hop pays for, each timed on its own: one benchmark per timed figure in the cost table
 * of the mesh demo's README. The inputs are built as the mesh builds them, at {@code payment} on the legitimate path
 * {@code gateway -> orders -> payment}: a keyring signed by a policy key, a root over the mesh's routes at the
 * mesh's proof depth, and the two-stamp chain {@code gateway} and {@code orders} sign, with its proof.
 *
 * <p>The settings below are the ones the README's numbers were taken with; JMH's command-line options override
 * them.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(1)
@Warmup(iterations = 3, time = 5)
@Measurement(iterations = 5, time = 5)
public class PrimitivesBenchmark {

    /** The routes of the mesh demo's {@code policy/paths.yaml}. */
    private static final List<List<String>> ROUTES = List.of(
            List.of("gateway", "orders", "payment"),
            List.of("gateway", "orders"),
            List.of("gateway", "search"),
            List.of("payment", "psp"),
            List.of("gateway", "tickets"),
            List.of("gateway", "tickets", "assistant"),
            List.of("gateway", "tickets", "assistant", "orders"),
            List.of("gateway", "tickets", "assistant", "payment"),
            List.of("gateway", "tickets", "assistant", "mailer"));

    /** The policy tool's default {@code PAZTPORT_PROOF_DEPTH}. */
    private static final int DEPTH = 8;

    private static final long DAY_MS = 24L * 60 * 60 * 1000;

    private String payMethod;
    private String payTarget;
    private byte[] payBody;
    private String route;
    private byte[] root;
    private MerkleProof proof;
    private byte[] stampBytes;
    private byte[] stampSig;
    private PrivateKey ordersKey;
    private PublicKey ordersPublic;

    @Setup
    public void setUp() {
        KeyPair policy = Crypto.generateEd25519KeyPair();
        KeyPair gateway = Crypto.generateEd25519KeyPair();
        KeyPair orders = Crypto.generateEd25519KeyPair();
        KeyPair payment = Crypto.generateEd25519KeyPair();
        long notAfter = System.currentTimeMillis() + 7 * DAY_MS;

        Map<String, String> services = new LinkedHashMap<>();
        services.put("gateway", encode(gateway.getPublic()));
        services.put("orders", encode(orders.getPublic()));
        services.put("payment", encode(payment.getPublic()));
        String policyPin = encode(policy.getPublic());
        KeyringFile ringFile = KeyringFile.sign(services, policyPin, notAfter, policy.getPrivate());
        require(ringFile.verifies(policyPin), "the keyring verifies under its pin");
        Keyring keyring = Keyring.fromFile(ringFile);

        PolicyBuilder.Result policyResult = PolicyBuilder.build(ROUTES, DEPTH, notAfter, policy.getPrivate());
        require(policyResult.signedRoot().verify(policy.getPublic()), "the root verifies under the policy key");
        root = policyResult.signedRoot().rootBytes();
        ProofBundle gatewayBundle = policyResult.bundles().get("gateway");
        ProofBundle ordersBundle = policyResult.bundles().get("orders");

        Stamper gatewayStamper = stamper("gateway", gateway.getPrivate(), true);
        Stamper ordersStamper = stamper("orders", orders.getPrivate(), false);
        Stamper.Stamped toOrders = gatewayStamper.next(List.of(), "orders",
                RequestBinding.compute("POST", "/orders", utf8("{\"item\":\"widget\"}")), List.of(), gatewayBundle);
        payMethod = "POST";
        payTarget = "/pay";
        payBody = utf8("{\"amount\":100}");
        Stamper.Stamped toPayment = ordersStamper.next(toOrders.chain(), "payment",
                RequestBinding.compute(payMethod, payTarget, payBody), List.of(), ordersBundle);
        require(toPayment.chain().size() == 2, "the chain at payment has two stamps");

        route = Routes.join(List.of("gateway", "orders", "payment"));
        proof = MerkleProof.decode(toPayment.proof().encode());
        require(proof.verify(route, root), "the route's proof verifies");

        Stamp last = toPayment.chain().get(1);
        stampBytes = last.signingBytes();
        stampSig = Base64Url.decode(last.sig());
        ordersKey = orders.getPrivate();
        ordersPublic = keyring.keyFor("orders");
        require(Crypto.verify(ordersPublic, stampBytes, stampSig), "orders' stamp verifies");
    }

    /** Merkle proof verify (depth 8): the leaf from the salt and the route, then eight node hashes to the root. */
    @Benchmark
    public boolean merkleProofVerify() {
        return proof.verify(route, root);
    }

    /**
     * The request binding of the {@code POST /pay} that {@code orders} sends, the base64url SHA-256 of its method,
     * target and body joined by newlines: what the caller computes to stamp the request and {@code payment}
     * recomputes to check it.
     */
    @Benchmark
    public String requestBinding() {
        return RequestBinding.compute(payMethod, payTarget, payBody);
    }

    /** Ed25519 sign of one stamp's signed bytes, with the JDK's provider. */
    @Benchmark
    public byte[] ed25519Sign() {
        return Crypto.sign(ordersKey, stampBytes);
    }

    /** Ed25519 verify of one stamp's signature, with the JDK's provider. */
    @Benchmark
    public boolean ed25519Verify() {
        return Crypto.verify(ordersPublic, stampBytes, stampSig);
    }

    /**
     * A stamper as the Spring starter makes one in the mesh: the instance is the container's hostname (12 hex
     * characters under Docker), a random UUID per request id, and the wall clock in milliseconds.
     */
    private static Stamper stamper(String svc, PrivateKey key, boolean origin) {
        String inst = HexFormat.of().formatHex(Crypto.randomBytes(6));
        return new Stamper(svc, inst, key, origin, () -> UUID.randomUUID().toString(), System::currentTimeMillis);
    }

    private static String encode(PublicKey key) {
        return Base64Url.encode(Crypto.encodePublicKey(key));
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static void require(boolean holds, String what) {
        if (!holds) {
            throw new IllegalStateException("benchmark setup: expected that " + what);
        }
    }
}
