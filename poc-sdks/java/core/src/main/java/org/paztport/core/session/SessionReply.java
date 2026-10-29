// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Map;
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
 * <p>{@code serverKeyringNotAfter} is the validity window of the keyring {@code serverKeyringSig} signs, null for
 * an old-form keyring, so it belongs to the entry-key form only. As on the request, its presence decides which
 * bytes that signature is checked over. A server root's own {@code notAfter} travels inside the root object.
 */
public record SessionReply(SignedRoot serverRoot, String serverPolicyKey, Map<String, String> serverKeyring,
        String serverKeyringSig, Long serverKeyringNotAfter, ReplyCert serverReplyCert, String nonce, String sess,
        String status, List<String> disabled, String sig) {

    public SessionReply {
        serverKeyring = Map.copyOf(serverKeyring);
        disabled = List.copyOf(disabled);
    }

    /**
     * The wire form: a null root is JSON null, and {@code serverKeyringSig}, {@code serverKeyringNotAfter},
     * {@code serverReplyCert} and {@code sig} are each left out while null.
     */
    public ObjectNode toJson() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.set("serverRoot", Sessions.rootJson(serverRoot));
        o.put("serverPolicyKey", serverPolicyKey);
        ObjectNode ring = o.putObject("serverKeyring");
        serverKeyring.forEach(ring::put);
        if (serverKeyringSig != null) {
            o.put("serverKeyringSig", serverKeyringSig);
        }
        if (serverKeyringNotAfter != null) {
            o.put("serverKeyringNotAfter", serverKeyringNotAfter);
        }
        if (serverReplyCert != null) {
            o.set("serverReplyCert", serverReplyCert.toJson());
        }
        o.put("nonce", nonce);
        o.put("sess", sess);
        o.put("status", status);
        ArrayNode off = o.putArray("disabled");
        disabled.forEach(off::add);
        if (sig != null) {
            o.put("sig", sig);
        }
        return o;
    }
}
