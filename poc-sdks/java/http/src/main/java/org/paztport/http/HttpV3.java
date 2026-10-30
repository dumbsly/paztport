// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.StampV3;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.VerifierV3;
import org.paztport.core.verify.VerifyInputV3;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.internal.VerifyInputs;

/**
 * Everything a transport needs to carry v3 over HTTP, with no web framework: the header encodings, the request's
 * verify input, and the check of a response's attestation.
 *
 * <p>Every header holds base64url of UTF-8 JSON, and decodes to that JSON's text as it arrived. The decoders never
 * throw. A header that is absent decodes to {@code null} (or {@code []} for influence), and one that is present but
 * unreadable decodes to the JSON string {@code "malformed"}, which no verifier check accepts, so the verifier names
 * the reason ({@code CHAIN_MISSING}, {@code INFLUENCE_MISMATCH}) instead of this layer guessing at it.
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
    /** What an unreadable header decodes to: the JSON string {@code "malformed"}, which no verifier check accepts. */
    private static final String MALFORMED = "\"malformed\"";
    private static final String NONE = "[]";

    private HttpV3() {
    }

    // --- Header encodings ---

    public static String encodeChain(List<StampV3> chain) {
        return encodeJson(Chains.toJson(chain));
    }

    /** The chain's JSON text: blank or absent gives {@code null}; unreadable gives {@code "malformed"}. */
    public static String decodeChain(String header) {
        return header == null || header.isBlank() ? null : readableOrMalformed(header);
    }

    public static String encodeProof(MerkleProof proof) {
        return proof == null ? null : proof.encode();
    }

    /** The proof's JSON text: absent or unreadable gives {@code null}, which the verifier answers as no proof. */
    public static String decodeProof(String header) {
        return header == null || header.isBlank() ? null : decodeJson(header);
    }

    /** {@code null} for an empty list, so no header is sent. */
    public static String encodeInfluence(List<InfluenceEntry> entries) {
        return entries == null || entries.isEmpty() ? null : encodeJson(Influence.toJson(entries));
    }

    /** The influence's JSON text: absent gives {@code []}; unreadable gives {@code "malformed"}. */
    public static String decodeInfluence(String header) {
        return header == null || header.isBlank() ? NONE : readableOrMalformed(header);
    }

    /**
     * The header value for JSON text the SDK wrote: base64url of its UTF-8, in exactly the bytes headers have always
     * carried. The text is read back and written out as bytes, which writes a character outside the Basic
     * Multilingual Plane as an escaped surrogate pair rather than as its four UTF-8 bytes.
     */
    private static String encodeJson(String json) {
        try {
            return Base64Url.encode(MAPPER.writeValueAsBytes(MAPPER.readTree(json)));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to encode JSON", e);
        }
    }

    private static String readableOrMalformed(String header) {
        String json = decodeJson(header);
        return json == null ? MALFORMED : json;
    }

    /**
     * The header's JSON text exactly as it arrived, once it is known to be base64url of UTF-8 holding one JSON value;
     * otherwise null. The text, not a tree, is handed on, so the verifier reads exactly what was sent.
     */
    private static String decodeJson(String header) {
        try {
            byte[] bytes = Base64Url.decode(header.strip());
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            JsonNode node = MAPPER.readTree(text);
            return node == null || node.isMissingNode() ? null : text;
        } catch (IllegalArgumentException | CharacterCodingException | JsonProcessingException e) {
            return null;
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
        String chain = decodeChain(chainHeader);
        return VerifyInputs.request(chain, Chains.parse(chain, false), proofHeader, influenceHeader, method, target,
                body, receiver, peer);
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
        StringWriter out = new StringWriter();
        try (JsonGenerator g = MAPPER.getFactory().createGenerator(out)) {
            g.writeStartObject();
            g.writeFieldName("stamp");
            g.writeRawValue(stamp.toJson());
            g.writeFieldName("labels");
            g.writeRawValue(ContentLabel.toJson(labels));
            g.writeEndObject();
        } catch (IOException e) {
            throw new IllegalStateException("failed to encode JSON", e);
        }
        return encodeJson(out.toString());
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
        String envelope = decodeChain(responseHeader);
        Map<String, String> members = envelope == null ? null : members(envelope);
        if (sent.isEmpty() || members == null || !members.containsKey("stamp") || !members.containsKey("labels")) {
            return rejected(ReasonCode.CHAIN_MISSING, hash);
        }
        List<ContentLabel> labels;
        try {
            labels = ContentLabel.parseAll(members.get("labels"));
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
        List<String> chain = new ArrayList<>();
        sent.forEach(s -> chain.add(s.toJson()));
        chain.add(members.get("stamp"));
        String target = sent.get(sent.size() - 1).rcv();
        VerifyResult result = verifier.verify(new VerifyInputV3(array(chain), bind, NONE,
                sentProof == null ? null : sentProof.toJson(), caller, false, rid + "|" + target + "|resp", null));
        return new ResponseCheck(result, result.ok() ? List.copyOf(labels) : List.of(), hash);
    }

    /**
     * The members of the JSON object {@code json}, each value's text exactly as it appears there, with a repeated
     * name's last value winning as it does when the object is read as a whole; null when {@code json} is not one
     * object. The response stamp is handed on as this text, not as a tree written back out: written back, a number
     * too large for a double would come out as the string {@code "Infinity"}, which a field check would accept.
     */
    private static Map<String, String> members(String json) {
        Map<String, String> out = new HashMap<>();
        try (JsonParser p = MAPPER.getFactory().createParser(json)) {
            if (p.nextToken() != JsonToken.START_OBJECT) {
                return null;
            }
            while (p.nextToken() == JsonToken.FIELD_NAME) {
                String name = p.currentName();
                p.nextToken();
                int start = (int) p.currentTokenLocation().getCharOffset();
                p.skipChildren();
                p.finishToken();
                out.put(name, json.substring(start, (int) p.currentLocation().getCharOffset()));
            }
            return p.currentToken() == JsonToken.END_OBJECT && p.nextToken() == null ? out : null;
        } catch (IOException e) {
            return null;
        }
    }

    /** A JSON array of the given JSON texts, each written as it stands. */
    private static String array(List<String> values) {
        StringWriter out = new StringWriter();
        try (JsonGenerator g = MAPPER.getFactory().createGenerator(out)) {
            g.writeStartArray();
            for (String v : values) {
                g.writeRawValue(v);
            }
            g.writeEndArray();
        } catch (IOException e) {
            throw new IllegalStateException("failed to encode JSON", e);
        }
        return out.toString();
    }

    private static ResponseCheck rejected(ReasonCode reason, String hash) {
        return new ResponseCheck(new VerifyResult(reason, "", ""), List.of(), hash);
    }
}
