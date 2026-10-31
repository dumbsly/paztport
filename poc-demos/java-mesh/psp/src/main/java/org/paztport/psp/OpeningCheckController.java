// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.influence.InfluenceEntry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checks an opening the shop shows against the entry the PSP received, so the demo can show the shop proving what
 * a blinded entry stood for, and failing to when it misstates it. Whether it opens is the SDK's question
 * ({@link BoundaryInfluence#opens}); this only finds the entry of the opening's class and owner among what
 * {@link ReceivedInfluence} recorded for the rid.
 *
 * <p>Present only when {@code paztport.openings=true}, under {@code /debug}, which the partner filter skips as
 * control plane: a demo stand-in for a dispute the PSP would settle by its own process, not part of the
 * attestation model.
 */
@RestController
@ConditionalOnProperty(name = "paztport.openings", havingValue = "true")
public class OpeningCheckController {

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private static final Set<String> REQUIRED = Set.of("cls", "salt", "originals");
    private static final Set<String> MEMBERS = Set.of("cls", "owner", "salt", "originals");

    private final ReceivedInfluence received;

    public OpeningCheckController(ReceivedInfluence received) {
        this.received = received;
    }

    /**
     * {@code {"opens": true|false}}. The body must be exactly one JSON object in strict UTF-8, with only whitespace
     * after it, or the answer is {@code 400}. An object that is not an opening, because it has a member other than
     * {@code cls}, {@code owner}, {@code salt} and {@code originals}, lacks one of the required three, or is refused
     * by {@link BoundaryInfluence.Opening#parse}, does not open: {@code 200} with {@code false}, as a checker must
     * answer for a malformed opening. {@code 404} when no call of {@code rid} was recorded, or it carried no entry of
     * the opening's class and owner. Only JSON is taken: any other content type is answered {@code 415}.
     */
    @PostMapping(path = "/debug/check-opening", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> check(@RequestParam String rid, @RequestBody byte[] body) {
        String text;
        JsonNode tree;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body)).toString();
            tree = JSON.readTree(text);
        } catch (CharacterCodingException | JsonProcessingException e) {
            return malformed();
        }
        if (tree == null || !tree.isObject()) {
            return malformed();
        }
        if (!hasExactlyTheMembers(tree)) {
            return ResponseEntity.ok(Map.of("opens", false));
        }
        BoundaryInfluence.Opening opening;
        try {
            // The text as sent, so a number reaches the SDK as it was written, never through a double.
            opening = BoundaryInfluence.Opening.parse(text);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.ok(Map.of("opens", false));
        }
        List<InfluenceEntry> entries = received.received(rid).orElse(null);
        if (entries == null) {
            return ResponseEntity.notFound().build();
        }
        // One entry per class and owner, so the first match is the only one.
        InfluenceEntry sent = entries.stream()
                .filter(e -> e.cls() == opening.cls() && Objects.equals(e.owner(), opening.owner()))
                .findFirst().orElse(null);
        if (sent == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("opens", BoundaryInfluence.opens(sent, opening)));
    }

    private static ResponseEntity<Map<String, Object>> malformed() {
        return ResponseEntity.badRequest().body(Map.of("reason", "MALFORMED_OPENING"));
    }

    /** Whether the object has {@code cls}, {@code salt} and {@code originals}, optionally {@code owner}, no more. */
    private static boolean hasExactlyTheMembers(JsonNode object) {
        Set<String> names = new HashSet<>();
        object.fieldNames().forEachRemaining(names::add);
        return names.containsAll(REQUIRED) && MEMBERS.containsAll(names);
    }
}
