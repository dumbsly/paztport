// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import org.paztport.core.internal.Json;
import org.paztport.core.internal.JsonIntegers;
import org.paztport.core.internal.RootJson;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/**
 * The client's half of the session handshake. {@code clientRoot} is null to ask for an unsafe session.
 * {@code clientKeyringSig} is null when the field is absent, which is how a request recorded before keyrings were
 * signed looks; a present but malformed one is read as the empty string, which never verifies.
 *
 * <p>{@code clientKeyringNotAfter} is the keyring's validity window, null for an old-form keyring. It travels
 * beside the keyring rather than inside it because the keyring's wire form is a bare map of service keys. Its
 * presence decides which bytes the keyring signature is checked over ({@link #clientKeyringFile}), so dropping or
 * altering it fails that signature, as tampering with any listed key does. It is not part of the session id, which
 * binds the keyring's services and the policy key, not the keyring's signature.
 */
public record SessionRequest(SignedRoot clientRoot, String clientPolicyKey, Map<String, String> clientKeyring,
        String clientKeyringSig, Long clientKeyringNotAfter, String nonce) {

    public SessionRequest {
        clientKeyring = Map.copyOf(clientKeyring);
    }

    /**
     * A request presenting {@code keyring} whole: its services, signature and validity window, so none of them can
     * be left behind.
     */
    public static SessionRequest of(SignedRoot clientRoot, String clientPolicyKey, KeyringFile keyring, String nonce) {
        return new SessionRequest(clientRoot, clientPolicyKey, keyring.services(), keyring.sig(), keyring.notAfter(),
                nonce);
    }

    /**
     * Reads a request, throwing {@link IllegalArgumentException} on a shape error (the spec's Invalid params), text
     * that is not one JSON value included. A missing {@code clientKeyringSig} is legacy (null); a present one that
     * is not a string reads as the empty string, which never verifies. The client root is read whole by
     * {@link SignedRoot#parse}, its {@code notAfter} included. A present {@code clientKeyringNotAfter}, or a client
     * root {@code notAfter}, that is not an integer in [0, 2^53 &minus; 1] (judged by value) is a shape error rather
     * than an absent field: read as absent, a damaged window would pass for the old form.
     */
    public static SessionRequest parse(String json) {
        return fromTree(json == null ? null : Json.tree(json));
    }

    /**
     * {@link #parse(String)} over a request body as it arrived: bytes in whichever Unicode encoding their
     * first bytes show, UTF-8 with or without a byte order mark included.
     */
    public static SessionRequest parse(byte[] json) {
        return fromTree(json == null ? null : Json.tree(json));
    }

    private static SessionRequest fromTree(JsonNode params) {
        if (params == null || !params.isObject()) {
            throw new IllegalArgumentException("session request must be an object");
        }
        JsonNode r = params.get("clientRoot");
        SignedRoot root = null;
        if (r == null || !(r.isNull() || r.isObject())) {
            throw new IllegalArgumentException("clientRoot must be an object or null");
        }
        if (r.isObject()) {
            root = RootJson.read(r);
        }
        JsonNode ring = params.get("clientKeyring");
        if (ring == null || !ring.isObject()) {
            throw new IllegalArgumentException("clientKeyring must be an object");
        }
        String sig = null;
        if (params.has("clientKeyringSig")) {
            sig = params.get("clientKeyringSig").isTextual() ? params.get("clientKeyringSig").textValue() : "";
        }
        Long ringNotAfter = null;
        if (params.has("clientKeyringNotAfter")) {
            ringNotAfter = JsonIntegers.notAfter(params.get("clientKeyringNotAfter"));
            if (ringNotAfter == null) {
                throw new IllegalArgumentException("clientKeyringNotAfter must be an integer in [0, 2^53 - 1]");
            }
        }
        return new SessionRequest(root, Sessions.text(params.get("clientPolicyKey"), "clientPolicyKey"),
                Sessions.stringMap(ring), sig, ringNotAfter, Sessions.text(params.get("nonce"), "nonce"));
    }

    /** True for a request with no {@code clientKeyringSig} field at all. */
    public boolean legacy() {
        return clientKeyringSig == null;
    }

    /**
     * The client's keyring as the request presents it, in its own form: whoever checks it against a pin calls
     * {@link KeyringFile#verifies} on this, so the signed bytes always follow {@code clientKeyringNotAfter}.
     */
    public KeyringFile clientKeyringFile() {
        return new KeyringFile(clientKeyring, clientPolicyKey, clientKeyringSig, clientKeyringNotAfter);
    }

    /**
     * The wire form; an absent keyring signature stays absent, and {@code clientKeyringNotAfter} is written only
     * for a new-form keyring.
     */
    public String toJson() {
        return Json.text(tree());
    }

    ObjectNode tree() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.set("clientRoot", Sessions.rootJson(clientRoot));
        o.put("clientPolicyKey", clientPolicyKey);
        ObjectNode ring = o.putObject("clientKeyring");
        clientKeyring.forEach(ring::put);
        if (clientKeyringSig != null) {
            o.put("clientKeyringSig", clientKeyringSig);
        }
        if (clientKeyringNotAfter != null) {
            o.put("clientKeyringNotAfter", clientKeyringNotAfter);
        }
        o.put("nonce", nonce);
        return o;
    }
}
