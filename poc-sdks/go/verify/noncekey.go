// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// NonceKey returns a chain's key in the replay cache (verification.md, Freshness and replay): the JCS text of
// the array of parts, each written as RFC 8785 writes strings. A part cannot run into its neighbour, because
// the quotes and escapes delimit it. It refuses a part that is not valid UTF-8, which has no text to key.
func NonceKey(parts ...string) (string, error) {
	var b strings.Builder
	b.WriteByte('[')
	for i, p := range parts {
		text, err := json.HashedText(p)
		if err != nil {
			return "", err
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(text)
	}
	b.WriteByte(']')
	return b.String(), nil
}
