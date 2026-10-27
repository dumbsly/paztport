// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.paztport.core.Base64Url;
import org.paztport.core.Bindings;
import org.paztport.core.ParsedChain;
import org.paztport.core.Chains;
import org.paztport.core.ContentLabel;
import org.paztport.core.Crypto;
import org.paztport.core.Influence;
import org.paztport.core.InfluenceEntry;
import org.paztport.core.MerkleProof;
import org.paztport.core.Peer;
import org.paztport.core.ReasonCode;
import org.paztport.core.RecordedStamp;
import org.paztport.core.StampV3;
import org.paztport.core.VerifierV3;
import org.paztport.core.VerifyInputV3;
import org.paztport.core.VerifyResult;

/**
 * Everything a transport needs to carry v3 over HTTP, with no web framework: the header encodings, the request's
 * verify input, and the check of a response's attestation.
 *
 * <p>Every header holds base64url of UTF-8 JSON. The decoders never throw. A header that is absent decodes to
 * {@code null} (or {@code []} for influence), and one that is present but unreadable decodes to the string
 * {@code "malformed"}, which no verifier check accepts, so the verifier names the reason ({@code CHAIN_MISSING},
 * {@code INFLUENCE_MISMATCH}) instead of this layer guessing at it.
 *
 * <p>A response is attested by one more stamp on the request chain the responder received, naming the caller as
 * receiver and binding the result hash, the request's {@code rid} and the content labels. The caller already holds
 * the route's proof, so the response carries none. Nonce keys are {@code <rid>|<last svc>|req} for a request and
 * {@code <rid>|<target>|resp} for a response; as in v1, a service calls a given receiver at most once per request
 * tree.
 */
public final class HttpV3 {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final JsonNode MALFORMED = TextNode.valueOf("malformed");

    private HttpV3() {
    }

    // --- Header encodings ---

    public static String encodeChain(List<StampV3> chain) {
        ArrayNode a = JsonNodeFactory.instance.arrayNode();
        chain.forEach(s -> a.add(s.toJson()));
        return encodeJson(a);
    }

    /** Blank or absent gives {@code null}; unreadable gives {@code "malformed"}. */
    public static JsonNode decodeChain(String header) {
        return header == null || header.isBlank() ? null : decodeJson(header);
    }

    public static String encodeProof(MerkleProof proof) {
        return proof == null ? null : proof.encode();
    }

    /** Absent or unreadable gives {@code null}, which the verifier answers as no proof. */
    public static JsonNode decodeProof(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        JsonNode node = decodeJson(header);
        return node == MALFORMED ? null : node;
    }

    /** {@code null} for an empty list, so no header is sent. */
    public static String encodeInfluence(List<InfluenceEntry> entries) {
        return entries == null || entries.isEmpty() ? null : encodeJson(Influence.toJson(entries));
    }

    /** Absent gives {@code []}; unreadable gives {@code "malformed"}. */
    public static JsonNode decodeInfluence(String header) {
        return header == null || header.isBlank() ? JsonNodeFactory.instance.arrayNode() : decodeJson(header);
    }

    private static String encodeJson(JsonNode node) {
        try {
            return Base64Url.encode(MAPPER.writeValueAsBytes(node));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to encode JSON", e);
        }
    }

    private static JsonNode decodeJson(String header) {
        try {
            byte[] bytes = Base64Url.decode(header.strip());
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            JsonNode node = MAPPER.readTree(text);
            return node == null || node.isMissingNode() ? MALFORMED : node;
        } catch (IllegalArgumentException | CharacterCodingException | JsonProcessingException e) {
            return MALFORMED;
        }
    }

    // --- Requests ---

    /**
     * The verify input for a received request. {@code target} is the raw path plus {@code ?} and the raw query, as
     * {@link RequestBinding} binds it. The nonce key is read from the chain when it parses, else empty: such a
     * chain is rejected before the nonce is consulted.
     */
    public static VerifyInputV3 request(String chainHeader, String proofHeader, String influenceHeader, String method,
            String target, byte[] body, String receiver, Peer peer) {
        JsonNode chain = decodeChain(chainHeader);
        return new VerifyInputV3(chain, RequestBinding.compute(method, target, body), decodeInfluence(influenceHeader),
                decodeProof(proofHeader), receiver, true, requestNonceKey(chain), peer);
    }

    private static String requestNonceKey(JsonNode chain) {
        ParsedChain parsed = Chains.parse(chain, false);
        if (!parsed.ok()) {
            return "";
        }
        List<RecordedStamp> stamps = parsed.stamps();
        return stamps.get(0).rid() + "|" + stamps.get(stamps.size() - 1).svc() + "|req";
    }

    // --- Responses ---

    /** {@code b64url(SHA-256(utf8("http-response\n" + status + "\n") || body))}, so no other status passes. */
    public static String resultHash(int status, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] prefix = ("http-response\n" + status + "\n").getBytes(StandardCharsets.UTF_8);
        out.write(prefix, 0, prefix.length);
        out.write(body, 0, body.length);
        return Base64Url.encode(Crypto.sha256(out.toByteArray()));
    }

    public static String encodeResponse(StampV3 stamp, List<ContentLabel> labels) {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.set("stamp", stamp.toJson());
        ArrayNode a = o.putArray("labels");
        labels.forEach(l -> a.add(l.toJson()));
        return encodeJson(o);
    }

    /** What a caller learns from a response. {@code labels} is empty unless the result is {@code OK}. */
    public record ResponseCheck(VerifyResult result, List<ContentLabel> labels, String resultHash) {
    }

    /**
     * Verifies a response by the live order on the chain the caller sent plus the response stamp: the receiver is
     * the caller, the route is the request's own (so {@code sentProof} is the proof the caller sent), and there is
     * no influence and no peer. Never throws: an unreadable header or labels are {@code CHAIN_MISSING}, and a
     * {@code rid} the binding cannot carry is {@code BINDING_MISMATCH}, as the spec asks of a verifier that cannot
     * compute a binding. Labels are returned only when the stamp commits to them.
     */
    public static ResponseCheck verifyResponse(VerifierV3 verifier, List<StampV3> sent, MerkleProof sentProof,
            String responseHeader, int status, byte[] body, String caller) {
        String hash = resultHash(status, body);
        JsonNode envelope = decodeChain(responseHeader);
        if (sent.isEmpty() || envelope == null || !envelope.isObject() || !envelope.has("stamp")
                || !envelope.has("labels")) {
            return rejected(ReasonCode.CHAIN_MISSING, hash);
        }
        List<ContentLabel> labels;
        try {
            labels = ContentLabel.parseAll(envelope.get("labels"));
        } catch (IllegalArgumentException e) {
            return rejected(ReasonCode.CHAIN_MISSING, hash);
        }
        String rid = sent.get(0).rid();
        String bind;
        try {
            bind = Bindings.response(hash, rid, labels);
        } catch (IllegalArgumentException e) {
            return rejected(ReasonCode.BINDING_MISMATCH, hash);
        }
        ArrayNode chain = JsonNodeFactory.instance.arrayNode();
        sent.forEach(s -> chain.add(s.toJson()));
        chain.add(envelope.get("stamp"));
        String target = sent.get(sent.size() - 1).rcv();
        VerifyResult result = verifier.verify(new VerifyInputV3(chain, bind, JsonNodeFactory.instance.arrayNode(),
                sentProof == null ? null : MAPPER.valueToTree(sentProof), caller, false, rid + "|" + target + "|resp",
                null));
        return new ResponseCheck(result, result.ok() ? List.copyOf(labels) : List.of(), hash);
    }

    private static ResponseCheck rejected(ReasonCode reason, String hash) {
        return new ResponseCheck(new VerifyResult(reason, "", ""), List.of(), hash);
    }
}
