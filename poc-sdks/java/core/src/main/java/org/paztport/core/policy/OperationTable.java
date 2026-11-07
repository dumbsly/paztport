// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;

/**
 * A service's operation table, {@code ops-<service>.json}: the operations an HTTP service names, each a method and
 * a path template. A caller that holds the table names the operation each call invokes in its stamp's
 * {@code rcv} ({@code orders#createOrder}), and the receiver confirms it from its own routing with {@link #match}.
 *
 * <p>The signed root covers a table as the route {@code <service>/ops:<hash>}, see {@link #route()}, and a service
 * and its callers must not use a table the root does not cover, see {@link #coveredBy}. The service's own bundle
 * holds that proof, and so does the bundle of each caller that names one of its operations.
 *
 * <p>A template is {@code /}, or {@code /} and non-empty segments joined with {@code /}, each {@code {}}, which
 * matches any one non-empty segment, or literal text, which matches itself.
 */
public record OperationTable(String service, List<Operation> operations) {

    /** One operation: its name (a route node holding no {@code #}), HTTP method and path template. */
    public record Operation(String name, String method, String template) {
    }

    private static final Set<String> MEMBERS = Set.of("operations", "service", "v");
    private static final Set<String> OPERATION_MEMBERS = Set.of("method", "name", "template");
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
        Set<String> shapes = new HashSet<>();
        for (Operation o : operations) {
            Routes.requireValidOperation(o.name());
            if (!names.add(o.name())) {
                throw new IllegalArgumentException("two operations are named " + o.name());
            }
            requireMethod(o.method());
            requireTemplate(o.template());
            if (!shapes.add(o.method() + " " + o.template())) {
                throw new IllegalArgumentException("two operations share the method " + o.method()
                        + " and the template " + o.template());
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
            JsonFields.exactly(op, OPERATION_MEMBERS, Set.of());
            operations.add(new Operation(JsonFields.string(op, "name"), JsonFields.string(op, "method"),
                    JsonFields.string(op, "template")));
        }
        return new OperationTable(JsonFields.string(o, "service"), operations);
    }

    private JsonValue json() {
        List<JsonValue> items = new ArrayList<>();
        for (Operation op : operations) {
            Map<String, JsonValue> m = new LinkedHashMap<>();
            m.put("method", new JsonValue.Str(op.method()));
            m.put("name", new JsonValue.Str(op.name()));
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
     * query and not percent-decoded, so a caller that holds a request target with a query strips it first. Of the
     * templates that match, the one with a literal segment at the first segment where they differ wins.
     */
    public String match(String method, String rawPath) {
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
            if (!matches(segments, path)) {
                continue;
            }
            if (best == null || prefersLiteral(segments, bestSegments)) {
                best = op;
                bestSegments = segments;
            }
        }
        return best == null ? null : best.name();
    }

    /** The name of the operation with exactly this method and template, or null. */
    public String operationFor(String method, String template) {
        for (Operation op : operations) {
            if (op.method().equals(method) && op.template().equals(template)) {
                return op.name();
            }
        }
        return null;
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
