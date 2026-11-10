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

    private static String keyedOp(String key, String name, String template) {
        return "{\"key\":" + key + ",\"method\":\"POST\",\"name\":\"" + name + "\",\"template\":\""
                + template + "\"}";
    }

    private static OperationTable keyed() {
        return OperationTable.read(file("items", "1",
                keyedOp("{\"segment\":1}", "reserve", "/items/{}/reserve"),
                "{\"key\":{\"query\":\"line\"},\"method\":\"GET\",\"name\":\"getLine\","
                        + "\"template\":\"/lines\"}",
                op("GET", "plain", "/plain/{}")));
    }

    @Test
    void readsSegmentAndQueryKeys() {
        OperationTable t = keyed();

        assertEquals(OperationTable.Key.segment(1), t.operation("reserve").key());
        assertEquals(128, t.operation("reserve").key().limit());
        assertEquals(OperationTable.Key.query("line"), t.operation("getLine").key());
        assertNull(t.operation("plain").key());
        assertNull(t.operation("nope"));
        assertEquals(t, OperationTable.read(t.toFile()));
    }

    @ParameterizedTest
    @MethodSource("malformedKeys")
    void refusesMalformedKeys(String keyJson, String template) {
        String text = file("items", "1", keyedOp(keyJson, "reserve", template));
        assertThrows(IllegalArgumentException.class, () -> OperationTable.read(text));
    }

    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> malformedKeys() {
        String one = "/items/{}/reserve";
        return java.util.stream.Stream.of(
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":1,\"query\":\"a\"}", one),
                org.junit.jupiter.params.provider.Arguments.of("{}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":1,\"other\":1}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":0}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":2}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":1}", "/charge"),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":\"1\"}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"query\":\"a|b\"}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"query\":\"\"}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":1,\"maxLength\":0}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":1,\"maxLength\":1025}", one),
                org.junit.jupiter.params.provider.Arguments.of("{\"segment\":1,\"maxLength\":\"128\"}", one),
                org.junit.jupiter.params.provider.Arguments.of("[]", one));
    }

    @Test
    void refusesAQueryKeyNamedByItsEntrancesCondition() {
        String text = file("p", "1",
                op("POST", "charge", "/charge"),
                "{\"key\":{\"query\":\"mode\"},\"method\":\"POST\",\"name\":\"refund\","
                        + "\"query\":{\"mode\":\"refund\"},\"template\":\"/charge\"}");
        assertThrows(IllegalArgumentException.class, () -> OperationTable.read(text));
        String other = file("p", "1",
                "{\"key\":{\"query\":\"mode\"},\"method\":\"POST\",\"name\":\"charge\","
                        + "\"template\":\"/charge\"}",
                "{\"method\":\"POST\",\"name\":\"refund\",\"query\":{\"mode\":\"refund\"},"
                        + "\"template\":\"/charge\"}");
        assertThrows(IllegalArgumentException.class, () -> OperationTable.read(other));
    }

    @Test
    void explicitDefaultMaxLengthKeepsItsHash() {
        String with = file("items", "1", keyedOp("{\"maxLength\":128,\"segment\":1}", "reserve", "/items/{}"));
        String without = file("items", "1", keyedOp("{\"segment\":1}", "reserve", "/items/{}"));
        OperationTable a = OperationTable.read(with);
        OperationTable b = OperationTable.read(without);

        assertFalse(a.hash().equals(b.hash()));
        assertEquals(a.hash(), OperationTable.read(a.toFile()).hash());
        assertEquals(b.hash(), OperationTable.read(b.toFile()).hash());
        assertEquals(128, a.operation("reserve").key().limit());
    }

    @Test
    void keyValueFromSegmentAndQuery() {
        OperationTable t = keyed();

        assertEquals("A1", t.keyValue("reserve", "/items/A1/reserve", null));
        assertEquals("L-7", t.keyValue("getLine", "/lines", "line=L-7"));
        assertEquals("L-7", t.keyValue("getLine", "/lines", "x=1&line=L-7"));
    }

    @Test
    void noKeyValue() {
        OperationTable t = keyed();
        String long129 = "a".repeat(129);

        assertNull(t.keyValue("reserve", "/items/%41/reserve", null));
        assertNull(t.keyValue("reserve", "/items/./reserve", null));
        assertNull(t.keyValue("reserve", "/items/../reserve", null));
        assertNull(t.keyValue("reserve", "/items/" + long129 + "/reserve", null));
        assertNull(t.keyValue("reserve", "/items//reserve", null));
        assertNull(t.keyValue("getLine", "/lines", "line=%41"));
        assertNull(t.keyValue("getLine", "/lines", null));
        assertNull(t.keyValue("getLine", "/lines", "line=a&line=b"));
        assertNull(t.keyValue("getLine", "/lines", "line"));
        assertNull(t.keyValue("getLine", "/lines", "line="));
        assertNull(t.keyValue("plain", "/plain/x", null));
        assertNull(t.keyValue("nope", "/items/A1/reserve", null));
        assertNull(t.keyValue("reserve", "/other/A1/reserve", null));
    }

    /**
     * A server decodes parameter names, and some split a query at {@code ;}, so the handler could read another
     * {@code line} than the one counted: a query key gives none then. Values of other parameters are not restricted.
     */
    @Test
    void noQueryKeyValueWhereANameIsEncodedOrTheQuerySplitsAtSemicolons() {
        OperationTable t = keyed();

        assertNull(t.keyValue("getLine", "/lines", "%6Cine=B&line=A"));
        assertNull(t.keyValue("getLine", "/lines", "x=1;line=B&line=A"));
        assertNull(t.keyValue("getLine", "/lines", "a%5B%5D=1&line=A"));
        assertEquals("A", t.keyValue("getLine", "/lines", "line=A&q=%41"));
        assertEquals("getLine", t.match("GET", "/lines", "%6Cine=B&line=A"));
    }

    @Test
    void raisedMaxLength() {
        OperationTable t = OperationTable.read(file("items", "1",
                keyedOp("{\"maxLength\":256,\"segment\":1}", "reserve", "/items/{}"),
                keyedOp("{\"maxLength\":1024,\"segment\":1}", "big", "/big/{}")));

        assertEquals("a".repeat(200), t.keyValue("reserve", "/items/" + "a".repeat(200), null));
        assertNull(t.keyValue("reserve", "/items/" + "a".repeat(257), null));
        assertEquals(1024, t.operation("big").key().limit());
    }
}
