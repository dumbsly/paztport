// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * A service's operation table, {@code ops-<service>.json}: the operations an HTTP service names, each a method and
 * a path template, and where an entrance serves several, a query condition. A caller that holds the table names
 * the operation each call invokes in its stamp's {@code rcv} ({@code orders#createOrder}), using {@link #match} to
 * find it. The receiver does not use {@code match}: it confirms its operation from its own routing, the handler
 * its framework dispatches to.
 *
 * <p>The signed root covers a table as the route {@code <service>/ops:<hash>}, see {@link #route()}, and a service
 * and its callers must not use a table the root does not cover, see {@link #coveredBy}. The service's own bundle
 * holds that proof, and so does the bundle of each service holding a route that ends at the service, whether or not
 * that route names an operation.
 *
 * <p>A template is {@code /}, or {@code /} and non-empty segments joined with {@code /}, each {@code {}}, which
 * matches any one non-empty segment, or literal text, which matches itself.
 *
 * <p>An operation may declare a {@link Key}: a path segment (a {@code {}} of its template, counted from 1) or a
 * query parameter that names the item a call acts on, so that a caller calls it once per request tree for each
 * item. {@link #keyValue} reads a call's key value from its raw target. A key's {@code maxLength} is kept as the
 * file wrote it, so a table is hashed as read: one that writes the default, 128, hashes differently from one that
 * leaves it out.
 */
public record OperationTable(String service, List<Operation> operations) {

    /** A query condition: the call's query holds the parameter {@code parameter} with the value {@code value}. */
    public record Condition(String parameter, String value) {
    }

    /**
     * The key of an operation: what names the item a call acts on. Either the {@code {}} segment of the template at
     * position {@code segment} (from 1, counted over the {@code {}} segments) with {@code query} null, or the query
     * parameter {@code query} with {@code segment} 0. {@code maxLength} is the longest key value, or null where the
     * file leaves it out, which is {@link #DEFAULT_MAX_LENGTH}.
     */
    public record Key(int segment, String query, Integer maxLength) {

        /** The longest key value when the file gives no {@code maxLength}. */
        public static final int DEFAULT_MAX_LENGTH = 128;

        /** The largest {@code maxLength} a file may give. */
        public static final int MAX_LENGTH_LIMIT = 1024;

        /** Every rule of a key alone: {@link IllegalArgumentException} names the one broken. */
        public Key {
            if ((segment >= 1) == (query != null) || segment < 0) {
                throw new IllegalArgumentException(
                        "a key must have exactly one of a segment (from 1) and a query parameter");
            }
            if (query != null) {
                requireQueryToken(query, "a key query parameter name");
            }
            if (maxLength != null && (maxLength < 1 || maxLength > MAX_LENGTH_LIMIT)) {
                throw new IllegalArgumentException("a key maxLength must be from 1 to " + MAX_LENGTH_LIMIT);
            }
        }

        /** A key by the {@code {}} segment at {@code segment}, from 1, with the default length. */
        public static Key segment(int segment) {
            return new Key(segment, null, null);
        }

        /** A key by the query parameter {@code name}, with the default length. */
        public static Key query(String name) {
            return new Key(0, name, null);
        }

        /** The longest key value: {@code maxLength}, or {@link #DEFAULT_MAX_LENGTH} where the file left it out. */
        public int limit() {
            return maxLength == null ? DEFAULT_MAX_LENGTH : maxLength;
        }
    }

    /**
     * One operation: its name (a route node holding no {@code #}), HTTP method, path template and, where the
     * entrance it shares with other operations needs it, the query condition that tells it apart; null for none.
     * Its {@code key}, where it declares one, is null for none.
     */
    public record Operation(String name, String method, String template, Condition query, Key key) {

        /** An operation with no query condition and no key. */
        public Operation(String name, String method, String template) {
            this(name, method, template, null, null);
        }

        /** An operation with no key. */
        public Operation(String name, String method, String template, Condition query) {
            this(name, method, template, query, null);
        }
    }

    private static final Set<String> MEMBERS = Set.of("operations", "service", "v");
    private static final Set<String> OPERATION_MEMBERS = Set.of("method", "name", "template");
    private static final Set<String> OPTIONAL_OPERATION_MEMBERS = Set.of("key", "query");
    private static final Set<String> KEY_MEMBERS = Set.of("maxLength", "query", "segment");
    private static final String PARAMETER = "{}";
    private static final String DOMAIN = "operations\n";

    /** Every rule of the table: {@link IllegalArgumentException} names the one broken. */
    public OperationTable {
        Routes.requireValidService(service);
        operations = List.copyOf(operations);
        if (operations.isEmpty()) {
            throw new IllegalArgumentException("operations must not be empty");
        }
        Set<String> names = new HashSet<>();
        Map<String, Set<String>> entrances = new HashMap<>();
        Map<String, String> parameters = new HashMap<>();
        for (Operation o : operations) {
            Routes.requireValidOperation(o.name());
            if (!names.add(o.name())) {
                throw new IllegalArgumentException("two operations are named " + o.name());
            }
            requireMethod(o.method());
            requireTemplate(o.template());
            Condition q = o.query();
            if (q != null) {
                requireQueryToken(q.parameter(), "a query parameter name");
                requireQueryToken(q.value(), "a query value");
            }
            String entrance = o.method() + " " + o.template();
            if (q != null && !parameters.computeIfAbsent(entrance, k -> q.parameter()).equals(q.parameter())) {
                throw new IllegalArgumentException("the query conditions of the entrance " + entrance
                        + " name different parameters");
            }
            if (!entrances.computeIfAbsent(entrance, k -> new HashSet<>()).add(q == null ? null : q.value())) {
                throw new IllegalArgumentException(q == null
                        ? "two operations of the entrance " + entrance + " have no query condition"
                        : "two operations of the entrance " + entrance + " share the query condition "
                                + q.parameter() + "=" + q.value());
            }
        }
        for (Operation o : operations) {
            Key k = o.key();
            if (k == null) {
                continue;
            }
            if (k.query() == null) {
                long slots = Arrays.stream(o.template().substring(1).split("/", -1)).filter(PARAMETER::equals).count();
                if (k.segment() > slots) {
                    throw new IllegalArgumentException("the key segment " + k.segment() + " of " + o.name()
                            + " is beyond the " + slots + " {} segments of its template");
                }
            } else if (k.query().equals(parameters.get(o.method() + " " + o.template()))) {
                throw new IllegalArgumentException("the key query parameter " + k.query() + " of " + o.name()
                        + " is named by a query condition of its entrance");
            }
        }
    }

    /** Reads {@code ops-<service>.json} as a file; a file that cannot be read is an {@link UncheckedIOException}. */
    public static OperationTable load(Path file) {
        return fromJson(JsonReader.file(file));
    }

    /** Reads the text of a table file, as {@link #load} does. */
    public static OperationTable read(String fileText) {
        return fromJson(JsonReader.fileText(fileText));
    }

    private static OperationTable fromJson(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, MEMBERS, Set.of());
        if (JsonFields.integer(o, "v") != 1) {
            throw new IllegalArgumentException("member v must be 1");
        }
        List<Operation> operations = new ArrayList<>();
        for (JsonValue item : JsonFields.array(o, "operations")) {
            JsonValue.Obj op = JsonFields.object(item);
            JsonFields.exactly(op, OPERATION_MEMBERS, OPTIONAL_OPERATION_MEMBERS);
            Condition query = null;
            if (op.get("query") != null) {
                JsonValue.Obj q = JsonFields.object(op, "query");
                if (q.names().size() != 1) {
                    throw new IllegalArgumentException("member query must have exactly one member");
                }
                String parameter = q.names().iterator().next();
                query = new Condition(parameter, JsonFields.string(q, parameter));
            }
            operations.add(new Operation(JsonFields.string(op, "name"), JsonFields.string(op, "method"),
                    JsonFields.string(op, "template"), query, op.get("key") == null ? null : readKey(op)));
        }
        return new OperationTable(JsonFields.string(o, "service"), operations);
    }

    private static Key readKey(JsonValue.Obj op) {
        JsonValue.Obj k = JsonFields.object(op, "key");
        JsonFields.exactly(k, Set.of(), KEY_MEMBERS);
        if (k.get("segment") != null && k.get("query") != null) {
            throw new IllegalArgumentException("a key must have exactly one of segment and query");
        }
        int segment = 0;
        if (k.get("segment") != null) {
            long v = JsonFields.integer(k, "segment");
            if (v < 1 || v > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("a key segment must be 1 or more");
            }
            segment = (int) v;
        }
        Integer maxLength = null;
        if (k.get("maxLength") != null) {
            long v = JsonFields.integer(k, "maxLength");
            if (v < 1 || v > Key.MAX_LENGTH_LIMIT) {
                throw new IllegalArgumentException("a key maxLength must be from 1 to " + Key.MAX_LENGTH_LIMIT);
            }
            maxLength = (int) v;
        }
        return new Key(segment, k.get("query") == null ? null : JsonFields.string(k, "query"), maxLength);
    }

    private JsonValue json() {
        List<JsonValue> items = new ArrayList<>();
        for (Operation op : operations) {
            Map<String, JsonValue> m = new LinkedHashMap<>();
            if (op.key() != null) {
                Map<String, JsonValue> k = new LinkedHashMap<>();
                if (op.key().maxLength() != null) {
                    k.put("maxLength", new JsonValue.Int(op.key().maxLength()));
                }
                if (op.key().query() != null) {
                    k.put("query", new JsonValue.Str(op.key().query()));
                } else {
                    k.put("segment", new JsonValue.Int(op.key().segment()));
                }
                m.put("key", new JsonValue.Obj(k));
            }
            m.put("method", new JsonValue.Str(op.method()));
            m.put("name", new JsonValue.Str(op.name()));
            if (op.query() != null) {
                Map<String, JsonValue> q = new LinkedHashMap<>();
                q.put(op.query().parameter(), new JsonValue.Str(op.query().value()));
                m.put("query", new JsonValue.Obj(q));
            }
            m.put("template", new JsonValue.Str(op.template()));
            items.add(new JsonValue.Obj(m));
        }
        Map<String, JsonValue> m = new LinkedHashMap<>();
        m.put("operations", new JsonValue.Arr(items));
        m.put("service", new JsonValue.Str(service));
        m.put("v", new JsonValue.Int(1));
        return new JsonValue.Obj(m);
    }

    /** The table as a file in the spec's file format. */
    public String toFile() {
        return JsonWriter.file(json());
    }

    /** {@code b64url(H(utf8("operations\n" || JCS(table))))}. */
    public String hash() {
        byte[] domain = DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] body = JsonWriter.wire(json());
        byte[] all = new byte[domain.length + body.length];
        System.arraycopy(domain, 0, all, 0, domain.length);
        System.arraycopy(body, 0, all, domain.length, body.length);
        return Base64Url.encode(Crypto.sha256(all));
    }

    /** The route the signed root covers this table as: the service, then {@code ops:<hash>}. */
    public List<String> route() {
        return List.of(service, "ops:" + hash());
    }

    /**
     * The name of the operation a call invokes, or null when none matches. {@code rawPath} is the path as sent: no
     * query and not percent-decoded; {@code rawQuery} is the query as sent, also not decoded, or null when there is
     * none. A call that repeats a parameter an entrance's condition names matches none of that entrance's
     * operations. Of the templates that match, the one with a literal segment at the first segment where they
     * differ wins, and of one entrance the operation whose condition holds wins over the one with none.
     */
    public String match(String method, String rawPath, String rawQuery) {
        if (!rawPath.startsWith("/")) {
            return null;
        }
        String[] path = rawPath.substring(1).split("/", -1);
        Operation best = null;
        String[] bestSegments = null;
        for (Operation op : operations) {
            if (!op.method().equals(method)) {
                continue;
            }
            String[] segments = op.template().substring(1).split("/", -1);
            if (!matches(segments, path) || !queryAllows(op, rawQuery)) {
                continue;
            }
            if (best == null || prefersLiteral(segments, bestSegments)
                    || (op.template().equals(best.template()) && op.query() != null && best.query() == null)) {
                best = op;
                bestSegments = segments;
            }
        }
        return best == null ? null : best.name();
    }

    /** The operation of that name, or null. */
    public Operation operation(String name) {
        for (Operation op : operations) {
            if (op.name().equals(name)) {
                return op;
            }
        }
        return null;
    }

    /**
     * The key value of a call to {@code operation}, read from the raw target as {@link #match} reads it, or null when
     * the operation is unknown or declares no key, or the call gives none: the path does not match the operation's
     * template; for a query key, the raw query (null for none) does not hold the parameter exactly once with a
     * value; or the text is not one or more of {@code A-Z a-z 0-9 - . _ ~}, is {@code .} or {@code ..}, or is
     * longer than the key's limit. Nothing is percent-decoded, so an encoded value gives none.
     */
    public String keyValue(String operation, String rawPath, String rawQuery) {
        Operation op = operation(operation);
        if (op == null || op.key() == null || !rawPath.startsWith("/")) {
            return null;
        }
        String[] template = op.template().substring(1).split("/", -1);
        String[] path = rawPath.substring(1).split("/", -1);
        if (!matches(template, path)) {
            return null;
        }
        String value = null;
        if (op.key().query() == null) {
            int slot = 0;
            for (int i = 0; i < template.length && value == null; i++) {
                if (template[i].equals(PARAMETER) && ++slot == op.key().segment()) {
                    value = path[i];
                }
            }
        } else if (rawQuery != null) {
            int count = 0;
            for (String pair : rawQuery.split("&", -1)) {
                int eq = pair.indexOf('=');
                if ((eq < 0 ? pair : pair.substring(0, eq)).equals(op.key().query())) {
                    count++;
                    value = eq < 0 ? "" : pair.substring(eq + 1);
                }
            }
            if (count != 1) {
                return null;
            }
        }
        if (value == null || value.isEmpty() || value.length() > op.key().limit() || value.equals(".")
                || value.equals("..") || !isQueryToken(value)) {
            return null;
        }
        return value;
    }

    /** The name of the operation with exactly this method, template and query condition (null for none), or null. */
    public String operationFor(String method, String template, Condition query) {
        for (Operation op : operations) {
            if (op.method().equals(method) && op.template().equals(template) && Objects.equals(op.query(), query)) {
                return op.name();
            }
        }
        return null;
    }

    /**
     * Whether the query lets {@code op} match: its condition holds, or it has none and the call does not repeat the
     * parameter that the conditions of its entrance name.
     */
    private boolean queryAllows(Operation op, String rawQuery) {
        String parameter = op.query() != null ? op.query().parameter() : null;
        for (Operation other : operations) {
            if (parameter == null && other.query() != null && other.method().equals(op.method())
                    && other.template().equals(op.template())) {
                parameter = other.query().parameter();
            }
        }
        if (parameter == null) {
            return true;
        }
        int count = 0;
        String value = null;
        if (rawQuery != null) {
            for (String pair : rawQuery.split("&", -1)) {
                int eq = pair.indexOf('=');
                if ((eq < 0 ? pair : pair.substring(0, eq)).equals(parameter)) {
                    count++;
                    value = eq < 0 ? "" : pair.substring(eq + 1);
                }
            }
        }
        if (count > 1) {
            return false;
        }
        return op.query() == null || (count == 1 && op.query().value().equals(value));
    }

    /**
     * Whether {@code bundle} holds a proof for this table's route that proves it against one of {@code roots}, the
     * one with the proof's {@code rootId}. A proof that is malformed is no proof, so the answer is false.
     */
    public boolean coveredBy(ProofBundle bundle, List<SignedRoot> roots) {
        String route = Routes.join(route());
        try {
            MerkleProof proof = bundle.proofFor(route);
            if (proof == null) {
                return false;
            }
            for (SignedRoot root : roots) {
                if (root.rootId().equals(proof.rootId()) && proof.verify(route, root.rootBytes())) {
                    return true;
                }
            }
            return false;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean matches(String[] template, String[] path) {
        if (template.length != path.length) {
            return false;
        }
        for (int i = 0; i < template.length; i++) {
            if (template[i].equals(PARAMETER) ? path[i].isEmpty() : !template[i].equals(path[i])) {
                return false;
            }
        }
        return true;
    }

    /** Whether {@code a} has a literal where it first differs from {@code b}; the two matched one path. */
    private static boolean prefersLiteral(String[] a, String[] b) {
        for (int i = 0; i < a.length; i++) {
            if (!a[i].equals(b[i])) {
                return !a[i].equals(PARAMETER);
            }
        }
        return false;
    }

    private static void requireMethod(String method) {
        if (method.isEmpty() || !method.chars().allMatch(c -> c >= 'A' && c <= 'Z')) {
            throw new IllegalArgumentException("method must be one or more of the characters A to Z");
        }
    }

    private static boolean isQueryToken(String token) {
        return !token.isEmpty() && token.chars().allMatch(c -> (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || "-._~".indexOf(c) >= 0);
    }

    private static void requireQueryToken(String token, String what) {
        if (!isQueryToken(token)) {
            throw new IllegalArgumentException(what
                    + " must be one or more of the characters A-Z a-z 0-9 - . _ ~");
        }
    }

    private static void requireTemplate(String template) {
        if (!template.startsWith("/")) {
            throw new IllegalArgumentException("template must start with /");
        }
        if (template.equals("/")) {
            return;
        }
        for (String segment : template.substring(1).split("/", -1)) {
            if (segment.isEmpty()) {
                throw new IllegalArgumentException("template has an empty segment");
            }
            if (!segment.equals(PARAMETER) && segment.chars().anyMatch(c -> "{}?#".indexOf(c) >= 0)) {
                throw new IllegalArgumentException(
                        "template segment must be {} or literal text without any of { } ? #");
            }
        }
    }
}
