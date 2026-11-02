// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"cmp"
	"unicode/utf8"
)

// LessUTF16 reports whether a sorts before b when each is taken as its sequence of UTF-16 code units,
// compared as unsigned integers: the order RFC 8785 §3.2.3 sorts member names in. Go's < on strings
// compares UTF-8 bytes, which is code point order, and the two differ: U+1F600 is the code units D83D
// DE00, so it sorts before U+FB33 here, though its code point is greater.
//
// a and b are valid UTF-8, as every string a writer writes is; a byte of anything else reads as U+FFFD.
func LessUTF16(a, b string) bool {
	return compareUTF16(a, b) < 0
}

// compareUTF16 returns -1, 0 or +1 as a sorts before, with or after b in LessUTF16's order.
func compareUTF16(a, b string) int {
	for a != "" && b != "" {
		ra, na := utf8.DecodeRuneInString(a)
		rb, nb := utf8.DecodeRuneInString(b)
		if ra != rb {
			if ua, ub := leadUnit(ra), leadUnit(rb); ua != ub {
				return cmp.Compare(ua, ub)
			}
			// Two code points above U+FFFF with the same high surrogate: their low surrogates, which
			// follow their code points' order, decide.
			return cmp.Compare(ra, rb)
		}
		a, b = a[na:], b[nb:]
	}
	// One string has run out, and a prefix sorts first.
	return cmp.Compare(len(a), len(b))
}

// leadUnit returns the first UTF-16 code unit of r: r itself up to U+FFFF, and its high surrogate above.
func leadUnit(r rune) rune {
	if r <= 0xFFFF {
		return r
	}
	return 0xD800 + (r-0x10000)>>10
}
