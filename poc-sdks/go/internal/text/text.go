// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package text

import "unicode/utf8"

// Valid reports whether s is valid UTF-8: no overlong form, no surrogate code point, nothing past
// U+10FFFF and no sequence cut short.
func Valid(s string) bool {
	return utf8.ValidString(s)
}

// IsNoncharacter reports whether r is one of Unicode's 66 noncharacters: U+FDD0 to U+FDEF, and the last two
// code points of each plane (U+FFFE, U+FFFF, U+1FFFE, ... U+10FFFF).
func IsNoncharacter(r rune) bool {
	if r < 0 || r > utf8.MaxRune {
		return false
	}
	return 0xFDD0 <= r && r <= 0xFDEF || r&0xFFFE == 0xFFFE
}

// HasNoncharacter reports whether s holds a noncharacter. It reads s as UTF-8, so a caller checks Valid
// first: an invalid byte reads as U+FFFD, which is not a noncharacter.
func HasNoncharacter(s string) bool {
	for _, r := range s {
		if IsNoncharacter(r) {
			return true
		}
	}
	return false
}
