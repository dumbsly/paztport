// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.core.internal.JsonValue;
import org.paztport.core.internal.JsonWriter;
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

    public SessionReply {
        serverKeyring = Map.copyOf(serverKeyring);
        disabled = List.copyOf(disabled);
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
