// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.OperationTable.Operation;
import org.paztport.core.policy.PolicyBuilder;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;

/**
 * The files of a small mesh in which {@code gateway} calls {@code orders} and {@code payment}, and {@code orders}
 * calls {@code payment}, both of which name their operations, written as keygen and the policy tool write them.
 */
final class OperationWorld {

    /** The validity window of the fixture roots and keyrings: 2100-01-01, beyond any clock here. */
    static final long NOT_AFTER = 4_102_444_800_000L;

    /** Orders' table: what {@link Handlers} maps, less {@code GET /debug}. */
    static final OperationTable ORDERS = new OperationTable("orders", List.of(
            new Operation("getOrder", "GET", "/orders/{}"),
            new Operation("search", "GET", "/orders/search"),
            new Operation("createOrder", "POST", "/orders"),
            new Operation("getItem", "GET", "/items/{}")));

    /** Payment's table: one entrance of two operations, told apart by a query condition, and a third. */
    static final OperationTable PAYMENT = new OperationTable("payment", List.of(
            new Operation("charge", "POST", "/charge"),
            new Operation("refund", "POST", "/charge", new OperationTable.Condition("mode", "refund")),
            new Operation("pay", "POST", "/pay")));

    final KeyPair policy = Crypto.generateEd25519KeyPair();
    final KeyPair gateway = Crypto.generateEd25519KeyPair();
    final KeyPair orders = Crypto.generateEd25519KeyPair();
    final KeyPair payment = Crypto.generateEd25519KeyPair();
    final Path dir;

    OperationWorld(Path dir) {
        this.dir = dir;
    }

    /**
     * The routes of a policy that covers both tables and lets gateway reach each of orders' and payment's
     * operations.
     */
    static List<List<String>> routes() {
        return List.of(
                List.of("gateway", "orders#getOrder"), List.of("gateway", "orders#search"),
                List.of("gateway", "orders#createOrder"), List.of("gateway", "orders#getItem"),
                List.of("gateway", "payment#charge"), List.of("gateway", "payment#refund"),
                List.of("gateway", "payment#pay"), List.of("orders", "payment#charge"),
                ORDERS.route(), PAYMENT.route());
    }

    /** {@link #routes()} without {@code drop}. */
    static List<List<String>> routesWithout(List<String> drop) {
        List<List<String>> routes = new ArrayList<>(routes());
        routes.remove(drop);
        return routes;
    }

    /**
     * Writes the keys, a keyring holding gateway, orders and payment, the pin, both tables and the root and bundles
     * built from {@code routes}, and answers what was built.
     */
    PolicyBuilder.Result write(List<List<String>> routes) throws IOException {
        String pin = pub(policy);
        Files.writeString(dir.resolve("policy.pub"), pin + "\n");
        Files.writeString(dir.resolve("gateway.key"), Base64Url.encode(Crypto.encodePrivateKey(gateway.getPrivate())));
        Files.writeString(dir.resolve("orders.key"), Base64Url.encode(Crypto.encodePrivateKey(orders.getPrivate())));
        Files.writeString(dir.resolve("payment.key"),
                Base64Url.encode(Crypto.encodePrivateKey(payment.getPrivate())));
        Files.writeString(dir.resolve("keyring.json"), KeyringFile.sign(
                Map.of("gateway", pub(gateway), "orders", pub(orders), "payment", pub(payment)), pin, NOT_AFTER,
                policy.getPrivate()).toFile());
        Files.writeString(dir.resolve("ops-orders.json"), ORDERS.toFile());
        Files.writeString(dir.resolve("ops-payment.json"), PAYMENT.toFile());
        PolicyBuilder.Result built = PolicyBuilder.build(routes, 4, NOT_AFTER, policy.getPrivate());
        Files.writeString(dir.resolve("root.json"), built.signedRoot().toFile());
        for (Map.Entry<String, ProofBundle> bundle : built.bundles().entrySet()) {
            writeBundle(bundle.getValue());
        }
        return built;
    }

    /** Writes {@code bundle} as its service's {@code proofs-<service>.json}. */
    void writeBundle(ProofBundle bundle) throws IOException {
        Files.writeString(dir.resolve("proofs-" + bundle.service() + ".json"), bundle.toFile());
    }

    /** {@code bundle} with its proof of {@code table}'s route replaced by its proof of another route it holds. */
    static ProofBundle swapped(ProofBundle bundle, OperationTable table, List<String> other) {
        Map<String, MerkleProof> proofs = new HashMap<>(bundle.proofs());
        proofs.put(Routes.join(table.route()), bundle.proofFor(Routes.join(other)));
        return new ProofBundle(bundle.service(), bundle.rootId(), proofs);
    }

    Path file(String name) {
        return dir.resolve(name);
    }

    /** The properties of {@code service}, holding its key and bundle and the pinned trust, then {@code more}. */
    String[] service(String service, String... more) {
        return Stream.concat(Stream.of(
                "paztport.service-name=" + service,
                "paztport.key-path=" + file(service + ".key"),
                "paztport.proofs-path=" + file("proofs-" + service + ".json"),
                "paztport.keyring-path=" + file("keyring.json"),
                "paztport.root-path=" + file("root.json"),
                "paztport.policy-key-path=" + file("policy.pub")), Stream.of(more)).toArray(String[]::new);
    }

    private static String pub(KeyPair k) {
        return Base64Url.encode(Crypto.encodePublicKey(k.getPublic()));
    }
}
