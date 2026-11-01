// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.ContentLabel;
import org.paztport.core.influence.Influence;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
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
 * <p>Every header holds the base64url of an object's JCS bytes, and a decoder hands on the text of the JSON it holds
 * exactly as it arrived. The decoders never throw. A header that is absent decodes to {@code null} (or {@code []} for
 * influence), and one that is present but unreadable, its bytes not the JCS bytes of one JSON value, decodes to the
 * JSON string {@code "malformed"}, which no verifier check accepts, so the verifier names the reason
 * ({@code CHAIN_MISSING}, {@code INFLUENCE_MISMATCH}) instead of this layer guessing at it.
 *
 * <p>A response is attested by one more stamp on the request chain the responder received, naming the caller as
 * receiver and binding the result hash, the request's {@code rid} and the content labels. The caller already holds
 * the route's proof, so the response carries none. Nonce keys are {@code <rid>|<last svc>|req} for a request and
 * {@code <rid>|<target>|resp} for a response; a service calls a given receiver at most once per request
 * tree.
 */
public final class HttpV3 {

    /** What an unreadable header decodes to: the JSON string {@code "malformed"}, which no verifier check accepts. */
    private static final String MALFORMED = "\"malformed\"";
    private static final String NONE = "[]";

    private HttpV3() {
    }

    // --- Header encodings ---

    public static String encodeChain(List<StampV3> chain) {
        return token(Chains.toJson(chain));
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
        return entries == null || entries.isEmpty() ? null : token(Influence.toJson(entries));
    }

    /** The influence's JSON text: absent gives {@code []}; unreadable gives {@code "malformed"}. */
    public static String decodeInfluence(String header) {
        return header == null || header.isBlank() ? NONE : readableOrMalformed(header);
    }

    private static String readableOrMalformed(String header) {
        String json = decodeJson(header);
        return json == null ? MALFORMED : json;
    }

    /**
     * The header's JSON text, once the header is known to be a token: the base64url of an object's JCS bytes; otherwise
     * null. Those bytes are the only text of the value they hold, so the verifier reads exactly what was sent.
     */
    private static String decodeJson(String header) {
        try {
            return JsonWriter.text(JsonReader.token(header.strip()));
        } catch (IllegalArgumentException e) {
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
        return VerifyInputs.request(chain, Chains.parse(chain), proofHeader, influenceHeader, method, target,
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

    /** The response header: the base64url of the JCS bytes of {@code {labels, stamp}}. */
    public static String encodeResponse(StampV3 stamp, List<ContentLabel> labels) {
        return JsonWriter.token(new JsonValue.Obj(Map.of("stamp", JsonReader.wireText(stamp.toJson()),
                "labels", JsonReader.wireText(ContentLabel.toJson(labels)))));
    }

    /** The base64url of the value's JCS bytes, the form of every header that carries an object. */
    private static String token(String jcsText) {
        return Base64Url.encode(jcsText.getBytes(StandardCharsets.UTF_8));
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
        JsonValue.Obj attestation = sent.isEmpty() ? null : attestation(responseHeader);
        if (attestation == null) {
            return rejected(ReasonCode.CHAIN_MISSING, hash);
        }
        List<ContentLabel> labels;
        try {
            labels = ContentLabel.parseAll(JsonWriter.text(attestation.get("labels")));
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
        chain.add(JsonWriter.text(attestation.get("stamp")));
        String target = sent.get(sent.size() - 1).rcv();
        VerifyResult result = verifier.verify(new VerifyInputV3("[" + String.join(",", chain) + "]", bind, NONE,
                sentProof == null ? null : sentProof.toJson(), caller, false, rid + "|" + target + "|resp", null));
        return new ResponseCheck(result, result.ok() ? List.copyOf(labels) : List.of(), hash);
    }

    /**
     * The response header's object, read from its token with exactly {@code labels} and {@code stamp}; null for a
     * header that is absent or does not read as that.
     */
    private static JsonValue.Obj attestation(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        try {
            JsonValue.Obj o = JsonFields.object(JsonReader.token(header.strip()));
            JsonFields.exactly(o, Set.of("labels", "stamp"), Set.of());
            return o;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static ResponseCheck rejected(ReasonCode reason, String hash) {
        return new ResponseCheck(new VerifyResult(reason, "", ""), List.of(), hash);
    }
}
