// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package reason_test

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/reason"
)

// codes are every code the package defines.
var codes = []reason.Code{
	reason.OK, reason.ChainMissing, reason.BadOrigin, reason.BadSignature, reason.BrokenLink, reason.Expired,
	reason.RIDMismatch, reason.BindingMismatch, reason.Replay, reason.PathNotAllowed, reason.SessionUnknown,
	reason.InfluenceMismatch, reason.PeerMismatch, reason.PolicyExpired, reason.TimeMismatch,
	reason.PromptMismatch, reason.OutsideSession, reason.InfluenceDenied, reason.UnsafeSession,
}

// profile are the codes only the MCP profile and the client's local gate give, which the module leaves
// out with the profile.
var profile = []string{
	"PROOF_MISMATCH", "RULES_MISMATCH", "VERDICT_MISMATCH", "CLIENT_PATH_NOT_ALLOWED", "SCOPE_DENIED", "UNCHECKABLE",
}

// TestCodesAreTheSpecs checks the codes against the table in verification.md's "Reason codes": each code's
// text is a row of the table, and every row is a code here or one of the profile's.
func TestCodesAreTheSpecs(t *testing.T) {
	b, err := os.ReadFile("../../spec/verification.md")
	if err != nil {
		t.Fatalf("the spec can't be read: %v", err)
	}
	_, section, ok := strings.Cut(string(b), "\n## Reason codes\n")
	if !ok {
		t.Fatal(`verification.md has no "Reason codes" section`)
	}
	section, _, _ = strings.Cut(section, "\n## ")
	var rows []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([A-Z_]+)` \\|").FindAllStringSubmatch(section, -1) {
		rows = append(rows, m[1])
	}
	if len(rows) == 0 {
		t.Fatal("the reason code table has no rows")
	}
	for _, c := range codes {
		if !slices.Contains(rows, string(c)) {
			t.Errorf("%s is not in the spec's table", c)
		}
	}
	for _, r := range rows {
		if !slices.Contains(codes, reason.Code(r)) && !slices.Contains(profile, r) {
			t.Errorf("the spec's %s is not a code here", r)
		}
	}
	if len(rows) != len(codes)+len(profile) {
		t.Errorf("the table has %d rows, want %d", len(rows), len(codes)+len(profile))
	}
}
