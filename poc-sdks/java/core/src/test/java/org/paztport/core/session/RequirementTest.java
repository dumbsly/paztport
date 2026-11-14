// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.paztport.core.session.Requirement.Calls;

/** The rule of sessions.md, "A client that requires extensions"; {@code v4.json}'s sessionRequirement replays it. */
class RequirementTest {

    private final Requirement none = Requirement.NONE;
    private final Requirement strict = Requirement.of(Set.of("influence", "example"), false);
    private final Requirement loose = Requirement.of(Set.of("influence", "example"), true);

    @Test
    void aClientThatRequiresNothingAlwaysCallsAndCarriesNothing() {
        assertEquals(new Calls(true, List.of()), none.callsAfter(null, List.of()));
        assertEquals(new Calls(true, List.of()), none.callsAfter(ReplyCheck.UNSAFE, List.of("example")));
        assertEquals(new Calls(true, List.of()), none.callsAfter(ReplyCheck.BAD_SIGNATURE, List.of()));
    }

    @Test
    void onlyAnAttestedSessionLetsAStrictClientCall() {
        assertEquals(new Calls(true, List.of("example", "influence")),
                strict.callsAfter(ReplyCheck.ATTESTED, List.of("example", "influence")));
        assertEquals(new Calls(false, List.of()),
                strict.callsAfter(ReplyCheck.UNSAFE, List.of("example", "influence")));
        assertEquals(new Calls(false, List.of()), strict.callsAfter(null, List.of()));
        assertEquals(new Calls(false, List.of()), strict.callsAfter(ReplyCheck.EXTENSION_REQUIRED, List.of("example")));
        for (ReplyCheck check : ReplyCheck.values()) {
            assertEquals(check == ReplyCheck.ATTESTED, strict.callsAfter(check, List.of()).calls(), check.name());
        }
    }

    @Test
    void theSwitchCarriesOnlyWhatTheReplyListed() {
        assertEquals(new Calls(true, List.of("example")),
                loose.callsAfter(ReplyCheck.EXTENSION_REQUIRED, List.of("example")));
        assertEquals(new Calls(true, List.of()), loose.callsAfter(ReplyCheck.UNSAFE, List.of("example", "influence")));
        assertEquals(new Calls(true, List.of()), loose.callsAfter(ReplyCheck.BAD_SIGNATURE, List.of()));
        assertEquals(new Calls(true, List.of()), loose.callsAfter(null, List.of()));
        assertEquals(new Calls(true, List.of("example", "influence")),
                loose.callsAfter(ReplyCheck.ATTESTED, List.of("example", "influence")));
    }

    @Test
    void theNamesAreCheckedSortedAndOnce() {
        assertThrows(IllegalArgumentException.class, () -> Requirement.of(Set.of("Influence"), false));
        assertThrows(IllegalArgumentException.class, () -> Requirement.of(Set.of(""), false));
        assertEquals(List.of("a", "b", "c"), Requirement.of(Set.of("c", "a", "b"), false).extensions());
        assertThrows(UnsupportedOperationException.class, () -> strict.extensions().add("x"));
        assertTrue(loose.continueWithout());
        assertEquals(List.of(), none.extensions());
    }

    @Test
    void theCallsOfAnAttestedSessionCannotBeChangedByTheCaller() {
        Calls calls = strict.callsAfter(ReplyCheck.ATTESTED, List.of());
        assertThrows(UnsupportedOperationException.class, () -> calls.requires().add("x"));
    }
}
