// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Map;

/**
 * The server's half of the handshake. {@code status} is {@code "attested"} or {@code "unsafe"}; {@code disabled}
 * lists the tools refused in an unsafe session. {@code sig} is the server policy key's signature over every other
 * field, and is null until {@link Sessions#signReply} has set it.
 */
public record SessionReply(SignedRoot serverRoot, String serverPolicyKey, Map<String, String> serverKeyring,
        String nonce, String sess, String status, List<String> disabled, String sig) {

    public SessionReply {
        serverKeyring = Map.copyOf(serverKeyring);
        disabled = List.copyOf(disabled);
    }

    /** The wire form: a null root is JSON null, and {@code sig} is left out while it is null. */
    public ObjectNode toJson() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.set("serverRoot", Sessions.rootJson(serverRoot));
        o.put("serverPolicyKey", serverPolicyKey);
        ObjectNode ring = o.putObject("serverKeyring");
        serverKeyring.forEach(ring::put);
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
