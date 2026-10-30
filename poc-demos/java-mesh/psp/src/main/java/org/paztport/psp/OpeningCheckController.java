// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.psp;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ReceivedInfluence received;

    public OpeningCheckController(ReceivedInfluence received) {
        this.received = received;
    }

    /**
     * {@code {"opens": true|false}}; {@code 404} when no call of {@code rid} was recorded, or it carried no entry
     * of the opening's class and owner; {@code 400} for a body that is not an opening.
     *
     * <p>The body arrives as bytes and is read as this endpoint always has: leniently, in whichever Unicode
     * encoding its first bytes show, and up to the end of the first JSON value, whatever follows it. Bytes that are
     * not well-formed are a bad request. That first value is handed to {@link BoundaryInfluence.Opening#parse} as
     * text, token by token as it was sent, see {@link #firstValue}. Only JSON is taken: any other content type is
     * answered {@code 415}.
     */
    @PostMapping(path = "/debug/check-opening", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> check(@RequestParam String rid, @RequestBody byte[] body) {
        BoundaryInfluence.Opening opening;
        try {
            opening = BoundaryInfluence.Opening.parse(firstValue(body));
        } catch (IOException | IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("reason", "MALFORMED_OPENING"));
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

    /**
     * The body's first JSON value as text. The body is first read whole as a tree, which is this endpoint's own
     * reading: the encoding detected, a byte order mark skipped, anything after the first value ignored, and a body
     * that is not well-formed refused with an {@link IOException}. The value's tokens are then copied out one by one,
     * each number as the text it was sent in, never through a double: a tree written back would turn a number too
     * large for a double, such as {@code 1e400}, into the string {@code "Infinity"}, which the opening's string
     * fields would then accept.
     */
    private static String firstValue(byte[] body) throws IOException {
        JSON.readTree(body);
        StringWriter out = new StringWriter();
        try (JsonParser p = JSON.createParser(body); JsonGenerator g = JSON.createGenerator(out)) {
            JsonToken t = p.nextToken();
            if (t == null) {
                throw new IOException("no JSON value");
            }
            int depth = 0;
            do {
                if (t == JsonToken.VALUE_NUMBER_INT || t == JsonToken.VALUE_NUMBER_FLOAT) {
                    g.writeNumber(p.getText());
                } else {
                    g.copyCurrentEvent(p);
                }
                depth += t.isStructStart() ? 1 : t.isStructEnd() ? -1 : 0;
            } while (depth > 0 && (t = p.nextToken()) != null);
        }
        return out.toString();
    }
}
