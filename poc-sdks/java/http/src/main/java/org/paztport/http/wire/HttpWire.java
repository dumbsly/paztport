// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
import org.paztport.core.policy.MerkleProof;
import org.paztport.core.stamp.Bindings;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Chains;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.HandOver;
import org.paztport.core.verify.NonceKeys;
import org.paztport.core.verify.Peer;
import org.paztport.core.verify.ReasonCode;
import org.paztport.core.verify.Verifier;
import org.paztport.core.verify.VerifyInput;
import org.paztport.core.verify.VerifyResult;
import org.paztport.http.internal.VerifyInputs;

/**
 * Everything a transport needs to carry version 4 over HTTP, with no web framework: the header encodings, the
 * request's verify input, and the check of a response's attestation (spec wire.md, HTTP).
 *
 * <p>Every header holds the base64url of a value's JCS bytes, and a decoder hands on the text of the JSON it holds
 * exactly as it arrived. The decoders never throw. A header that is present but does not decode is left to the check
 * that reads it (spec verification.md, HTTP requests and responses): an unreadable chain decodes to the JSON string
 * {@code "malformed"}, which check 1 refuses ({@code CHAIN_MISSING}); unreadable blocks decode to text that does not
 * read as JSON, which check 9a refuses ({@code EXTENSION_MISMATCH}), never to {@code null}, which would be no blocks
 * at all; and an unreadable proof decodes to {@code null}, no proof ({@code PATH_NOT_ALLOWED}).
 *
 * <p>A response is attested by one more stamp on the request chain the responder received, naming the caller as
 * receiver, binding the result hash and the request's {@code rid}, and committing to the response's own block, which
 * travels beside it. The caller already holds the route's proof and the blocks it sent, so the response carries
 * neither. Nonce keys are the JCS text of an array of strings (spec verification.md, Freshness and replay):
 * {@code [rid, lastSvc, lastRcv, "req"]} for a request and {@code [rid, lastRcv, "resp"]} for a response,
 * {@code lastRcv} being the receiver the request chain's last stamp names, with the operation when it names one; a
 * service calls a given receiver, or a given operation of it, at most once per request tree. Where that operation
 * declares a key, the call's key value comes before the direction, {@code [rid, lastSvc, lastRcv, keyValue, "req"]}
 * and {@code [rid, lastRcv, keyValue, "resp"]}, so the operation is called at most once per request tree for each
 * item, and two items are two keys.
 */
public final class HttpWire {

    /** What an unreadable chain decodes to: the JSON string {@code "malformed"}, which no verifier check accepts. */
    private static final String MALFORMED = "\"malformed\"";
    /**
     * What blocks that do not decode decode to: text that does not read as JSON, so check 9a refuses it, and a
     * service serving without verifying refuses it too, whether or not the chain read.
     */
    private static final String UNREADABLE = "unreadable";

    private HttpWire() {
    }

    // --- Header encodings ---

    /**
     * A received Paztport header's value, or {@code null} when it is absent or blank: a blank header is read as an
     * absent one, and any other value as it arrived (spec wire.md, HTTP). A blank header asks for nothing an absent
     * one does not, since a caller can always leave the header out. Of the characters a field value may hold, read as
     * ISO-8859-1, only space and horizontal tab are blank.
     */
    public static String headerValue(String header) {
        return header == null || header.isBlank() ? null : header;
    }

    /** The {@code X-Path-Chain} header for {@code chain}. */
    public static String encodeChain(List<Stamp> chain) {
        return token(Chains.toJson(chain));
    }

    /** The chain's JSON text: blank or absent gives {@code null}; unreadable gives {@code "malformed"}. */
    public static String decodeChain(String header) {
        if (headerValue(header) == null) {
            return null;
        }
        String json = decodeJson(header);
        return json == null ? MALFORMED : json;
    }

    /** The {@code X-Path-Proof} header for {@code proof}, or {@code null} for none. */
    public static String encodeProof(MerkleProof proof) {
        return proof == null ? null : proof.encode();
    }

    /** The proof's JSON text: absent or unreadable gives {@code null}, which the verifier answers as no proof. */
    public static String decodeProof(String header) {
        return headerValue(header) == null ? null : decodeJson(header);
    }

    /**
     * The {@code X-Path-Extensions} header for {@code blocks}, one per stamp of the chain it travels with, in chain
     * order. Never {@code null}: a sender sends the header whatever its blocks hold.
     *
     * @throws IllegalArgumentException when the blocks' JCS text passes the wire limit, 256 KiB; nothing is dropped
     *     to make room
     */
    public static String encodeBlocks(List<Block> blocks) {
        return token(Block.toJson(blocks));
    }

    /**
     * The blocks' JSON text, as {@code VerifyInput.blocks} takes it: absent or blank gives {@code null}, which is one
     * empty block per stamp; a header that does not decode gives text that does not read as JSON, never
     * {@code null}, so check 9a refuses it.
     */
    public static String decodeBlocks(String header) {
        if (headerValue(header) == null) {
            return null;
        }
        String json = decodeJson(header);
        return json == null ? UNREADABLE : json;
    }

    /**
     * The header's JSON text, once the header is known to be a token: the base64url of a value's JCS bytes; otherwise
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
     *
     * @param blocksHeader the {@code X-Path-Extensions} header, or null when none came
     * @param keyValue the key value read from {@code target} where {@code receiver} names a keyed operation, which
     *     the nonce key then carries, or null for none
     */
    public static VerifyInput request(String chainHeader, String proofHeader, String blocksHeader, String method,
            String target, byte[] body, String receiver, String keyValue, Peer peer) {
        String chain = decodeChain(chainHeader);
        return VerifyInputs.request(chain, Chains.parse(chain), proofHeader, blocksHeader, method, target,
                body, receiver, keyValue, peer);
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

    /**
     * The {@code X-Path-Response} header: the base64url of the JCS bytes of {@code {block, stamp}}, the response
     * stamp and the block it commits to.
     *
     * @throws IllegalArgumentException when the header's JCS text passes the wire limit, 256 KiB
     */
    public static String encodeResponse(Stamp stamp, Block block) {
        return JsonWriter.token(new JsonValue.Obj(Map.of("block", JsonReader.wireText(block.toJson()),
                "stamp", JsonReader.wireText(stamp.toJson()))));
    }

    /** The base64url of the value's JCS bytes, the form of every header. */
    private static String token(String jcsText) {
        return Base64Url.encode(jcsText.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * What a caller learns from a response: the live order's result on it, whose hand-over holds what the blocks
     * hold for the names the caller acts on where the result is OK, and the response's result hash.
     */
    public record ResponseCheck(VerifyResult result, String resultHash) {

        /**
         * The response stamp's own entry under {@code name}, the last of the hand-over's, or null where the check did
         * not give OK or the caller does not act on {@code name}.
         */
        public HandOver.StampItems response(String name) {
            if (!result.ok()) {
                return null;
            }
            List<HandOver.StampItems> entries = result.handOver().under(name);
            return entries == null ? null : entries.get(entries.size() - 1);
        }
    }

    /**
     * Verifies a response by the live order on the chain the caller sent plus the response stamp, with the blocks it
     * sent plus the response's own (spec verification.md, A response, at the caller): the receiver is the caller, the
     * route is the request's own (so {@code sentProof} is the proof the caller sent), and there is no peer. Never
     * throws on what the response holds: a header that does not read as exactly {@code {block, stamp}}, a block that
     * does not read as a block included, is {@code CHAIN_MISSING}, and a {@code rid} the binding cannot carry is
     * {@code BINDING_MISMATCH}, as the spec asks of a verifier that cannot compute a binding.
     *
     * @param sentBlocks the blocks the call carried, one per stamp of {@code sent}
     * @param keyValue the key value of the target sent, where the sent chain's last stamp names a keyed operation,
     *     which the nonce key then carries, or null for none
     */
    public static ResponseCheck verifyResponse(Verifier verifier, List<Stamp> sent, List<Block> sentBlocks,
            MerkleProof sentProof, String header, int status, byte[] body, String caller, String keyValue) {
        Objects.requireNonNull(sentBlocks, "sentBlocks");
        String hash = resultHash(status, body);
        JsonValue.Obj attestation = sent.isEmpty() ? null : attestation(header);
        if (attestation == null) {
            return rejected(ReasonCode.CHAIN_MISSING, hash);
        }
        String block = JsonWriter.text(attestation.get("block"));
        try {
            Block.parseAll("[" + block + "]");
        } catch (IllegalArgumentException e) {
            return rejected(ReasonCode.CHAIN_MISSING, hash);
        }
        String rid = sent.get(0).rid();
        // The sent chain's last stamp names the receiver, operation included, and the key value joins the key when
        // there is one, so calls to two operations of one receiver, or for two items of one, spend two keys.
        String lastRcv = sent.get(sent.size() - 1).rcv();
        String bind;
        String nonceKey;
        try {
            bind = Bindings.response(hash, rid);
            nonceKey = keyValue == null ? NonceKeys.of(rid, lastRcv, "resp")
                    : NonceKeys.of(rid, lastRcv, keyValue, "resp");
        } catch (IllegalArgumentException e) {
            // a lone surrogate, which neither a binding nor a key can carry
            return rejected(ReasonCode.BINDING_MISMATCH, hash);
        }
        List<String> chain = new ArrayList<>();
        sent.forEach(s -> chain.add(s.toJson()));
        chain.add(JsonWriter.text(attestation.get("stamp")));
        // The blocks the caller sent, then the response's own, as JCS text the verifier reads for itself; text past
        // the wire limit is its to refuse.
        List<String> blocks = new ArrayList<>();
        sentBlocks.forEach(b -> blocks.add(b.toJson()));
        blocks.add(block);
        VerifyResult result = verifier.verify(new VerifyInput("[" + String.join(",", chain) + "]", bind,
                "[" + String.join(",", blocks) + "]", sentProof == null ? null : sentProof.toJson(), caller, false,
                nonceKey, null));
        return new ResponseCheck(result, hash);
    }

    /**
     * The response header's object, read from its token with exactly {@code block} and {@code stamp}; null for a
     * header that is absent or does not read as that.
     */
    private static JsonValue.Obj attestation(String header) {
        if (headerValue(header) == null) {
            return null;
        }
        try {
            JsonValue.Obj o = JsonFields.object(JsonReader.token(header.strip()));
            JsonFields.exactly(o, Set.of("block", "stamp"), Set.of());
            return o;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static ResponseCheck rejected(ReasonCode reason, String hash) {
        return new ResponseCheck(new VerifyResult(reason, "", "", null), hash);
    }
}
