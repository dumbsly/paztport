// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.paztport.core.encoding.MalformedJsonException;
import org.paztport.core.internal.JsonFields;
import org.paztport.core.internal.JsonReader;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
import org.paztport.core.internal.KeyringNames;
import org.paztport.core.internal.RootJson;
import org.paztport.core.policy.SignedRoot;

/**
 * The server's half of the handshake. {@code status} is {@code "attested"} or {@code "unsafe"}; {@code disabled}
 * lists the tools refused in an unsafe session. {@code sig} is the signature over every other field, and is null
 * until {@link Sessions#signReply} has set it.
 *
 * <p>The reply comes in two forms, told apart only by which fields are present. In the entry-key form,
 * {@code serverKeyringSig} (the policy key's signature over the keyring) and {@code serverReplyCert} (the policy
 * key's short-lived certificate for the entry service's key) are both set and {@code sig} is the entry service's,
 * so the policy key can stay offline. In the policy-key form both are null and {@code sig} is the policy key's.
 *
 * <p>{@code serverKeyringNotAfter} is the validity window of the keyring {@code serverKeyringSig} signs, so it
 * belongs to the entry-key form only, and is null in the policy-key form. As on the request, that signature is
 * checked over it. A server root's own {@code notAfter} travels inside the root object.
 */
public record SessionReply(SignedRoot serverRoot, String serverPolicyKey, Map<String, String> serverKeyring,
        String serverKeyringSig, Long serverKeyringNotAfter, ReplyCert serverReplyCert, String nonce, String sess,
        String status, List<String> disabled, String sig) {

    private static final Set<String> MEMBERS = Set.of("disabled", "nonce", "serverKeyring", "serverPolicyKey",
            "serverRoot", "sess", "sig", "status");
    private static final Set<String> ENTRY_KEY_FORM = Set.of("serverKeyringNotAfter", "serverKeyringSig",
            "serverReplyCert");

    public SessionReply {
        serverKeyring = Map.copyOf(serverKeyring);
        disabled = List.copyOf(disabled);
    }

    /**
     * Reads a reply from its wire bytes, given as text, throwing {@link IllegalArgumentException} for one that does
     * not read: a {@link MalformedJsonException} for text that is not exactly the canonical bytes of one value, and
     * otherwise a refusal naming the member. A reply has exactly its members: {@code serverRoot} {@code null} or a
     * root with exactly its own members, string {@code serverPolicyKey}, {@code nonce}, {@code sess} and
     * {@code sig}, a {@code serverKeyring} of strings under route-node names, {@code status} {@code "attested"} or
     * {@code "unsafe"}, a {@code disabled} array of strings, and, each only when present, a string
     * {@code serverKeyringSig}, which needs {@code serverKeyringNotAfter} beside it, an integer
     * {@code serverKeyringNotAfter}, and a {@code serverReplyCert} with exactly a certificate's members. A member
     * whose value is {@code null} is present.
     * Checks no signature: {@link Sessions#checkReply} reads a reply with this, then checks it.
     */
    public static SessionReply parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("a session reply must be a JSON object");
        }
        return fromTree(JsonReader.wireText(json));
    }

    /** {@link #parse(String)} over a reply body as it arrived: its wire bytes, read as they are. */
    public static SessionReply parse(byte[] json) {
        if (json == null) {
            throw new IllegalArgumentException("a session reply must be a JSON object");
        }
        return fromTree(JsonReader.wire(json));
    }

    /** The reply's schema. */
    private static SessionReply fromTree(JsonValue value) {
        JsonValue.Obj o = JsonFields.object(value);
        JsonFields.exactly(o, MEMBERS, ENTRY_KEY_FORM);
        JsonValue root = o.get("serverRoot");
        String status = JsonFields.string(o, "status");
        if (!status.equals("attested") && !status.equals("unsafe")) {
            throw new IllegalArgumentException("member status is neither attested nor unsafe");
        }
        List<String> disabled = new ArrayList<>();
        for (JsonValue item : JsonFields.array(o, "disabled")) {
            if (!(item instanceof JsonValue.Str s)) {
                throw new IllegalArgumentException("member disabled holds a value that is not a string");
            }
            disabled.add(s.value());
        }
        String ringSig = null;
        if (o.get("serverKeyringSig") != null) {
            ringSig = JsonFields.string(o, "serverKeyringSig");
            if (o.get("serverKeyringNotAfter") == null) {
                throw new IllegalArgumentException("no member serverKeyringNotAfter");
            }
        }
        Map<String, String> keyring = JsonFields.stringMap(o, "serverKeyring");
        KeyringNames.requireRouteNodes(keyring, "serverKeyring");
        return new SessionReply(root instanceof JsonValue.Null ? null : RootJson.read(root),
                JsonFields.string(o, "serverPolicyKey"), keyring, ringSig,
                o.get("serverKeyringNotAfter") == null ? null : JsonFields.integer(o, "serverKeyringNotAfter"),
                o.get("serverReplyCert") == null ? null : ReplyCert.fromTree(o.get("serverReplyCert")),
                JsonFields.string(o, "nonce"), JsonFields.string(o, "sess"), status, disabled,
                JsonFields.string(o, "sig"));
    }

    /**
     * The wire form: the object's JCS text. A null root is JSON null, and {@code serverKeyringSig},
     * {@code serverKeyringNotAfter}, {@code serverReplyCert} and {@code sig} are each left out while null.
     */
    public String toJson() {
        return JsonWriter.text(tree());
    }

    JsonValue.Obj tree() {
        Map<String, JsonValue> o = new LinkedHashMap<>();
        o.put("serverRoot", Sessions.rootJson(serverRoot));
        o.put("serverPolicyKey", new JsonValue.Str(serverPolicyKey));
        o.put("serverKeyring", Sessions.stringMapJson(serverKeyring));
        if (serverKeyringSig != null) {
            o.put("serverKeyringSig", new JsonValue.Str(serverKeyringSig));
        }
        if (serverKeyringNotAfter != null) {
            o.put("serverKeyringNotAfter", new JsonValue.Int(serverKeyringNotAfter));
        }
        if (serverReplyCert != null) {
            o.put("serverReplyCert", serverReplyCert.tree());
        }
        o.put("nonce", new JsonValue.Str(nonce));
        o.put("sess", new JsonValue.Str(sess));
        o.put("status", new JsonValue.Str(status));
        o.put("disabled", new JsonValue.Arr(disabled.stream().map(d -> (JsonValue) new JsonValue.Str(d)).toList()));
        if (sig != null) {
            o.put("sig", new JsonValue.Str(sig));
        }
        return new JsonValue.Obj(o);
    }
}
