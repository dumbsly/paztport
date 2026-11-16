// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The enum's comments say it holds the spec's reason codes, less the MCP profile's, which Java does not implement.
 * This test reads the table in verification.md, so a code added to the spec or dropped from the enum fails here.
 */
class ReasonCodeTest {

    /** The codes only the MCP profile and the client's local gate give. */
    private static final Set<String> PROFILE = Set.of("CLIENT_PATH_NOT_ALLOWED", "SCOPE_DENIED", "UNCHECKABLE",
            "PROOF_MISMATCH", "RULES_MISMATCH", "VERDICT_MISMATCH");

    private static final Pattern ROW = Pattern.compile("^\\| `([A-Z_]+)` \\|", Pattern.MULTILINE);

    @Test
    void theEnumIsTheSpecsTableLessTheProfilesCodes() throws IOException {
        Set<String> rows = new TreeSet<>();
        Matcher m = ROW.matcher(reasonCodesSection());
        while (m.find()) {
            rows.add(m.group(1));
        }
        assertFalse(rows.isEmpty(), "the reason code table has no rows");
        Set<String> expected = new TreeSet<>(rows);
        expected.removeAll(PROFILE);
        Set<String> names = new TreeSet<>();
        Arrays.stream(ReasonCode.values()).forEach(c -> names.add(c.name()));
        assertEquals(expected, names);
        // the six are in the table, so a rename in the spec cannot leave a stale exception here
        Set<String> profileRows = new TreeSet<>(rows);
        profileRows.retainAll(PROFILE);
        assertEquals(new TreeSet<>(PROFILE), profileRows);
    }

    /** The text of verification.md's "Reason codes" section, found by walking up from the working directory. */
    private static String reasonCodesSection() throws IOException {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path d = dir; d != null; d = d.getParent()) {
            Path candidate = d.resolve("spec/verification.md");
            if (Files.isRegularFile(candidate)) {
                String text = Files.readString(candidate);
                int start = text.indexOf("\n## Reason codes\n");
                assertFalse(start < 0, "verification.md has no \"Reason codes\" section");
                int end = text.indexOf("\n## ", start + 1);
                return text.substring(start, end < 0 ? text.length() : end);
            }
        }
        throw new IllegalStateException("spec/verification.md not found above " + dir);
    }
}
