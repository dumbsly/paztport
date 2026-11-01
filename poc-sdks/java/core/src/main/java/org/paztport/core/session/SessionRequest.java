// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.internal.RootJson;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.SignedRoot;

/**
 * The client's half of the session handshake. {@code clientRoot} is null to ask for an unsafe session.
 * {@code clientKeyringSig} is the client policy key's signature over its keyring, never null or empty.
 *
 * <p>{@code clientKeyringNotAfter} is the keyring's validity window. It travels beside the keyring rather than
 * inside it because the keyring's wire form is a bare map of service keys. The keyring signature is checked over it
 * ({@link #clientKeyringFile}), so altering it fails that signature, as tampering with any listed key does. It is
 * not part of the session id, which binds the keyring's services and the policy key, not the keyring's signature.
 */
public record SessionRequest(SignedRoot clientRoot, String clientPolicyKey, Map<String, String> clientKeyring,
        String clientKeyringSig, long clientKeyringNotAfter, String nonce) {

    private static final Set<String> MEMBERS = Set.of("clientKeyring", "clientKeyringNotAfter", "clientKeyringSig",
            "clientPolicyKey", "clientRoot", "nonce");

    public SessionRequest {
        Objects.requireNonNull(clientKeyringSig, "clientKeyringSig");
        if (clientKeyringSig.isEmpty()) {
            throw new IllegalArgumentException("clientKeyringSig must not be empty");
        }
        clientKeyring = Map.copyOf(clientKeyring);
    }

    /**
     * A request presenting {@code keyring} whole: its services, signature and validity window, so none of them can
     * be left behind. Throws {@link NullPointerException} for an unsigned keyring.
     */
    public static SessionRequest of(SignedRoot clientRoot, String clientPolicyKey, KeyringFile keyring, String nonce) {
        return new SessionRequest(clientRoot, clientPolicyKey, keyring.services(), keyring.sig(), keyring.notAfter(),
                nonce);
    }

    /**
     * Reads a request from its wire bytes, given as text, throwing {@link IllegalArgumentException} for one that
     * does not read (the spec's Invalid params): a {@link MalformedJsonException} for text that is not exactly the
     * canonical bytes of one value, and otherwise a refusal naming the member. A request has exactly its six members:
     * {@code clientRoot} {@code null} or a root, whole and with exactly its own members, string
     * {@code clientPolicyKey} and {@code nonce}, a {@code clientKeyring} of strings, a non-empty string
     * {@code clientKeyringSig}, and an integer {@code clientKeyringNotAfter}.
     */
    public static SessionRequest parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("a session request must be a JSON object");
        }
        return fromTree(JsonReader.wireText(json));
    }

    /** {@link #parse(String)} over a request body as it arrived: its wire bytes, read as they are. */
    public static SessionRequest parse(byte[] json) {
        if (json == null) {
            throw new IllegalArgumentException("a session request must be a JSON object");
        }
        return fromTree(JsonReader.wire(json));
    }

    /** The request's schema. */
    private static SessionRequest fromTree(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, MEMBERS, Set.of());
        JsonValue root = o.get("clientRoot");
        String ringSig = JsonFields.string(o, "clientKeyringSig");
        if (ringSig.isEmpty()) {
            throw new IllegalArgumentException("member clientKeyringSig is empty");
        }
        return new SessionRequest(root instanceof JsonValue.Null ? null : RootJson.read(root),
                JsonFields.string(o, "clientPolicyKey"), JsonFields.stringMap(o, "clientKeyring"), ringSig,
                JsonFields.integer(o, "clientKeyringNotAfter"), JsonFields.string(o, "nonce"));
    }

    /**
     * The client's keyring as the request presents it: whoever checks it against a pin calls
     * {@link KeyringFile#verifies} on this, so the signed bytes always cover {@code clientKeyringNotAfter}.
     */
    public KeyringFile clientKeyringFile() {
        return new KeyringFile(clientKeyring, clientPolicyKey, clientKeyringSig, clientKeyringNotAfter);
    }

    /** The wire form: the object's JCS text. */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    /** The request as a JSON value, for the writers of this SDK; not API. */
    public JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("clientRoot", Sessions.rootJson(clientRoot));
        o.put("clientPolicyKey", new JsonValue.Str(clientPolicyKey));
        o.put("clientKeyring", Sessions.stringMapJson(clientKeyring));
        o.put("clientKeyringSig", new JsonValue.Str(clientKeyringSig));
        o.put("clientKeyringNotAfter", new JsonValue.Int(clientKeyringNotAfter));
        o.put("nonce", new JsonValue.Str(nonce));
        return new JsonValue.Obj(o);
    }
}
