// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// serverCurrent judges each piece of the server's material the reply holds, and no other: a certificate
// with no keyring beside it is judged alone, and a keyring by its window.
func TestServerCurrentJudgesWhatTheReplyHolds(t *testing.T) {
	sig, window := "sig", int64(20)
	tests := []struct {
		name string
		r    Reply
		now  int64
		want bool
	}{
		{"nothing to judge", Reply{}, 30, true},
		{"a certificate alone, current", Reply{ServerReplyCert: &policy.ReplyCert{NotAfter: 20}}, 20, true},
		{"a certificate alone, past it", Reply{ServerReplyCert: &policy.ReplyCert{NotAfter: 20}}, 21, false},
		{"a keyring, current", Reply{ServerKeyringSig: &sig, ServerKeyringNotAfter: &window}, 20, true},
		{"a keyring, past it", Reply{ServerKeyringSig: &sig, ServerKeyringNotAfter: &window}, 21, false},
		{"a keyring signature with no window", Reply{ServerKeyringSig: &sig}, 30, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serverCurrent(tt.r, tt.now); got != tt.want {
				t.Fatalf("serverCurrent = %t, want %t", got, tt.want)
			}
		})
	}
}
