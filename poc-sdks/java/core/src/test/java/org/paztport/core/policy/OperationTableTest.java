// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

class OperationTableTest {

    private static final long NOT_AFTER = 4_102_444_800_000L;

    private static OperationTable orders() {
        return new OperationTable("orders", List.of(
                new OperationTable.Operation("createOrder", "POST", "/orders"),
                new OperationTable.Operation("findOrders", "GET", "/orders"),
                new OperationTable.Operation("getOrder", "GET", "/orders/{}"),
                new OperationTable.Operation("search", "GET", "/orders/search")));
    }

    private static String file(String service, String v, String... operations) {
        return "{\"operations\":[" + String.join(",", operations) + "],\"service\":\"" + service
                + "\",\"v\":" + v + "}";
    }

    private static String op(String method, String name, String template) {
        return "{\"method\":\"" + method + "\",\"name\":\"" + name + "\",\"template\":\"" + template + "\"}";
    }

    private static OperationTable payment() {
        return new OperationTable("payment", List.of(
                new OperationTable.Operation("charge", "POST", "/charge"),
                new OperationTable.Operation("refund", "POST", "/charge",
                        new OperationTable.Condition("mode", "refund")),
                new OperationTable.Operation("pay", "POST", "/pay")));
    }

    /** An operation member with a {@code query} written as given, JSON text. */
    private static String opq(String name, String template, String query) {
        return "{\"method\":\"POST\",\"name\":\"" + name + "\",\"query\":" + query + ",\"template\":\""
                + template + "\"}";
    }

    private static JsonValue json(OperationTable t) {
        List<JsonValue> ops = t.operations().stream().map(o -> {
            Map<String, JsonValue> m = new LinkedHashMap<>();
            m.put("method", new JsonValue.Str(o.method()));
            m.put("name", new JsonValue.Str(o.name()));
            if (o.query() != null) {
                m.put("query", new JsonValue.Obj(Map.of(o.query().parameter(), new JsonValue.Str(o.query().value()))));
            }
            m.put("template", new JsonValue.Str(o.template()));
            return (JsonValue) new JsonValue.Obj(m);
        }).toList();
        Map<String, JsonValue> m = new LinkedHashMap<>();
        m.put("operations", new JsonValue.Arr(ops));
        m.put("service", new JsonValue.Str(t.service()));
        m.put("v", new JsonValue.Int(1));
        return new JsonValue.Obj(m);
    }

    @Test
    void readsTheTableAndHashesIt() {
        OperationTable t = orders();
        byte[] domain = "operations\n".getBytes(StandardCharsets.UTF_8);
        byte[] body = JsonWriter.text(json(t)).getBytes(StandardCharsets.UTF_8);
        byte[] all = new byte[domain.length + body.length];
        System.arraycopy(domain, 0, all, 0, domain.length);
        System.arraycopy(body, 0, all, domain.length, body.length);

        assertEquals(Base64Url.encode(Crypto.sha256(all)), t.hash());
        assertEquals(List.of("orders", "ops:" + t.hash()), t.route());
        assertEquals(t, OperationTable.read(t.toFile()));
    }

    @Test
    void readsAQuery() {
        OperationTable t = payment();
        byte[] domain = "operations\n".getBytes(StandardCharsets.UTF_8);
        byte[] body = JsonWriter.text(json(t)).getBytes(StandardCharsets.UTF_8);
        byte[] all = new byte[domain.length + body.length];
        System.arraycopy(domain, 0, all, 0, domain.length);
        System.arraycopy(body, 0, all, domain.length, body.length);

        assertTrue(t.toFile().contains("\"query\""));
        assertEquals(t, OperationTable.read(t.toFile()));
        assertEquals(Base64Url.encode(Crypto.sha256(all)), t.hash());
    }

    static List<String> refused() {
        String create = op("POST", "createOrder", "/orders");
        String plain = op("POST", "charge", "/charge");
        return List.of(
                file("payment", "1", plain, opq("refund", "/charge", "{\"mode\":\"refund\",\"kind\":\"x\"}")),
                file("payment", "1", plain, opq("refund", "/charge", "{\"mode\":\"re/fund\"}")),
                file("payment", "1", plain, opq("refund", "/charge", "{\"mode\":\"\"}")),
                file("payment", "1", plain, opq("refund", "/charge", "\"mode=refund\"")),
                file("payment", "1", opq("refund", "/charge", "{\"mode\":\"refund\"}"),
                        opq("cancel", "/charge", "{\"kind\":\"x\"}")),
                file("payment", "1", opq("refund", "/charge", "{\"mode\":\"refund\"}"),
                        opq("cancel", "/charge", "{\"mode\":\"refund\"}")),
                file("orders", "1", op("POST", "create#Order", "/orders")),
                file("orders", "1", create, op("GET", "createOrder", "/orders/{}")),
                file("orders", "1", create, op("POST", "other", "/orders")),
                file("orders", "1", op("POST", "x", "orders")),
                file("orders", "1", op("POST", "x", "/orders//x")),
                file("orders", "1", op("POST", "x", "/orders/{id}")),
                file("orders", "1", op("POST", "x", "/a{}")),
                file("orders", "1", op("POST", "x", "/a?b")),
                file("orders", "1", op("get", "x", "/orders")),
                file("orders", "1"),
                file("orders", "2", create),
                file("a#b", "1", create),
                "{\"extra\":1,\"operations\":[" + create + "],\"service\":\"orders\",\"v\":1}",
                file("orders", "1", "{\"extra\":1,\"method\":\"POST\",\"name\":\"x\",\"template\":\"/\"}"));
    }

    @ParameterizedTest
    @MethodSource("refused")
    void refuses(String text) {
        assertThrows(IllegalArgumentException.class, () -> OperationTable.read(text));
    }

    @Test
    void matches() {
        OperationTable t = orders();
        assertEquals("search", t.match("GET", "/orders/search", null));
        assertEquals("getOrder", t.match("GET", "/orders/123", null));
        assertEquals("findOrders", t.match("GET", "/orders", null));
        assertEquals("createOrder", t.match("POST", "/orders", null));
        assertEquals("getOrder", t.match("GET", "/orders/a%2Fb", null));
        assertNull(t.match("GET", "/orders/", null));
        assertNull(t.match("GET", "/orders/123/items", null));
        assertNull(t.match("get", "/orders", null));
        assertNull(t.match("DELETE", "/orders", null));

        OperationTable two = new OperationTable("orders", List.of(
                new OperationTable.Operation("x", "GET", "/a/{}/c"),
                new OperationTable.Operation("y", "GET", "/a/b/{}")));
        assertEquals("y", two.match("GET", "/a/b/c", null));
    }

    @Test
    void namesTheEntranceRuleItBreaks() {
        String refund = opq("refund", "/charge", "{\"mode\":\"refund\"}");
        IllegalArgumentException different = assertThrows(IllegalArgumentException.class, () -> OperationTable.read(
                file("payment", "1", refund, opq("cancel", "/charge", "{\"kind\":\"refund\"}"))));
        assertTrue(different.getMessage().contains("different parameters"), different.getMessage());
        IllegalArgumentException same = assertThrows(IllegalArgumentException.class, () -> OperationTable.read(
                file("payment", "1", refund, opq("cancel", "/charge", "{\"mode\":\"refund\"}"))));
        assertTrue(same.getMessage().contains("share the query condition"), same.getMessage());
    }

    @Test
    void matchesAQuery() {
        OperationTable t = payment();
        assertEquals("refund", t.match("POST", "/charge", "mode=refund"));
        assertEquals("charge", t.match("POST", "/charge", null));
        assertEquals("charge", t.match("POST", "/charge", "mode=x"));
        assertEquals("charge", t.match("POST", "/charge", "other=1"));
        assertEquals("charge", t.match("POST", "/charge", "mode=%72efund"));
        assertEquals("refund", t.match("POST", "/charge", "other=1&mode=refund"));
        assertNull(t.match("POST", "/charge", "mode=refund&mode=refund"));
        assertEquals("pay", t.match("POST", "/pay", "mode=refund&mode=refund"));
        assertEquals("charge", t.match("POST", "/charge", "mode"));
        assertNull(t.match("POST", "/charge", "mode&mode=refund"));
        assertEquals("charge", t.match("POST", "/charge", ""));
    }

    @Test
    void operationForIsExact() {
        assertEquals("charge", payment().operationFor("POST", "/charge", null));
        assertEquals("refund", payment().operationFor("POST", "/charge",
                new OperationTable.Condition("mode", "refund")));
        assertNull(payment().operationFor("POST", "/charge", new OperationTable.Condition("mode", "x")));
        assertEquals("getOrder", orders().operationFor("GET", "/orders/{}", null));
        assertNull(orders().operationFor("GET", "/orders/{x}", null));
    }

    @Test
    void coveredByTheRootThatHoldsItsRoute() {
        OperationTable t = orders();
        KeyPair key = Crypto.generateEd25519KeyPair();
        PolicyBuilder.Result r = PolicyBuilder.build(
                List.of(t.route(), List.of("gateway", "orders#getOrder")), 8, NOT_AFTER, key.getPrivate());
        List<SignedRoot> roots = List.of(r.signedRoot());

        assertTrue(t.coveredBy(r.bundles().get("orders"), roots));
        assertTrue(t.coveredBy(r.bundles().get("gateway"), roots));

        OperationTable more = new OperationTable("orders", java.util.stream.Stream.concat(
                t.operations().stream(), java.util.stream.Stream.of(
                        new OperationTable.Operation("drop", "DELETE", "/orders/{}"))).toList());
        assertFalse(more.coveredBy(r.bundles().get("orders"), roots));
        assertFalse(more.coveredBy(r.bundles().get("gateway"), roots));

        PolicyBuilder.Result other = PolicyBuilder.build(
                List.of(t.route(), List.of("gateway", "orders#getOrder")), 8, NOT_AFTER, key.getPrivate());
        assertFalse(t.coveredBy(r.bundles().get("orders"), List.of(other.signedRoot())));
    }
}
