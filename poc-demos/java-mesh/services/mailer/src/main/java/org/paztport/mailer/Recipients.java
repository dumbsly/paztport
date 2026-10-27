// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.mailer;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The mailer's directory: whose each address is, from {@code mailer.recipients}. It is the mailer's own record, so
 * it gives the destination owner the rule judges an email by; the request names only the address. An address the
 * directory does not hold has no owner, and so no email shaped by someone's private data may go to it.
 */
@ConfigurationProperties(prefix = "mailer")
public class Recipients {

    private final Map<String, String> recipients;

    /** @param recipients each address to the customer it belongs to */
    public Recipients(Map<String, String> recipients) {
        Map<String, String> byAddress = new HashMap<>();
        if (recipients != null) {
            recipients.forEach((address, owner) -> byAddress.put(normalise(address), owner));
        }
        this.recipients = Map.copyOf(byAddress);
    }

    /** The owner of an address, after trimming and lower-casing it, or null when the directory has none. */
    public String ownerOf(String address) {
        return address == null ? null : recipients.get(normalise(address));
    }

    private static String normalise(String address) {
        return address.trim().toLowerCase(Locale.ROOT);
    }
}
