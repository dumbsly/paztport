// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.InfluenceClass;
import org.paztport.core.influence.InfluenceEntry;
import org.paztport.spring.partner.BoundaryClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Hands out the opening of one entry the egress sent the PSP, so the demo can show the PSP what a blinded entry
 * stood for. The salt and the opening come from the egress's {@link BoundaryClient}; this only finds the originals
 * {@link BoundaryOpenings} kept and asks for the group named.
 *
 * <p>With {@code tamper=true} the first original's {@code h} is replaced by the base64url of 32 zero bytes, which
 * is how the demo shows an opening that misstates the content not opening the entry.
 *
 * <p>Present only when {@code paztport.openings=true}, under {@code /debug}, which the inbound filter skips as
 * control plane: a demo stand-in for a disclosure the shop would make by its own process, not part of the
 * attestation model.
 */
@RestController
@ConditionalOnProperty(name = "paztport.openings", havingValue = "true")
public class OpeningController {

    private static final String ZERO_HASH = Base64Url.encode(new byte[32]);

    private final BoundaryOpenings openings;
    private final ObjectProvider<BoundaryClient> boundary;
    private final String partner;

    public OpeningController(BoundaryOpenings openings, ObjectProvider<BoundaryClient> boundary,
            @Value("${paztport.boundary.partner:}") String partner) {
        this.openings = openings;
        this.boundary = boundary;
        this.partner = partner;
    }

    /**
     * The opening of the entry for ({@code cls}, {@code owner}) of request {@code rid}, as {@code Opening.toJson()};
     * no {@code owner}, or an empty one, names the group with no owner. {@code 404} when no call of that rid to the
     * partner is held, or none of its originals is in the group; {@code 400} for a class that does not exist.
     *
     * <p>The body is exactly the text {@code Opening.toJson()} gives, handed to the web layer as a string.
     */
    @GetMapping("/debug/boundary-opening")
    public ResponseEntity<?> opening(@RequestParam String rid, @RequestParam String cls,
            @RequestParam(required = false) String owner, @RequestParam(defaultValue = "false") boolean tamper) {
        InfluenceClass group = InfluenceClass.fromWire(cls);
        if (group == null) {
            return ResponseEntity.badRequest().body(Map.of("reason", "UNKNOWN_CLASS"));
        }
        List<InfluenceEntry> originals = openings.originals(rid, partner).orElse(null);
        BoundaryClient client = boundary.getIfAvailable();
        if (originals == null || client == null) {
            return ResponseEntity.notFound().build();
        }
        BoundaryInfluence.Opening opening;
        try {
            opening = client.opening(rid, group, owner == null || owner.isEmpty() ? null : owner, originals);
        } catch (IllegalArgumentException e) {
            // No original is in that group: the call sent no entry for it.
            return ResponseEntity.notFound().build();
        }
        String body = (tamper ? tampered(opening) : opening).toJson();
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(body);
    }

    /** The same opening with its first original's {@code h} zeroed: the content it claims is not what was sent. */
    private static BoundaryInfluence.Opening tampered(BoundaryInfluence.Opening opening) {
        List<InfluenceEntry> originals = new ArrayList<>(opening.originals());
        InfluenceEntry first = originals.get(0);
        originals.set(0, new InfluenceEntry(first.cls(), first.src(), ZERO_HASH, first.cid(), first.owner()));
        return new BoundaryInfluence.Opening(opening.cls(), opening.owner(), opening.salt(), originals);
    }
}
