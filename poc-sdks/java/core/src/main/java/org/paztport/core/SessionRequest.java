// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;

/**
 * The client's half of the session handshake. {@code clientRoot} is null to ask for an unsafe session.
 * {@code clientKeyringSig} is null when the field is absent, which is how a request recorded before keyrings were
 * signed looks; a present but malformed one is read as the empty string, which never verifies.
 */
public record SessionRequest(SignedRoot clientRoot, String clientPolicyKey, Map<String, String> clientKeyring,
        String clientKeyringSig, String nonce) {

    public SessionRequest {
        clientKeyring = Map.copyOf(clientKeyring);
    }

    /** True for a request with no {@code clientKeyringSig} field at all. */
    public boolean legacy() {
        return clientKeyringSig == null;
    }

    /** The wire form; an absent keyring signature stays absent. */
    public ObjectNode toJson() {
        ObjectNode o = JsonNodeFactory.instance.objectNode();
        o.set("clientRoot", Sessions.rootJson(clientRoot));
        o.put("clientPolicyKey", clientPolicyKey);
        ObjectNode ring = o.putObject("clientKeyring");
        clientKeyring.forEach(ring::put);
        if (clientKeyringSig != null) {
            o.put("clientKeyringSig", clientKeyringSig);
        }
        o.put("nonce", nonce);
        return o;
    }
}
