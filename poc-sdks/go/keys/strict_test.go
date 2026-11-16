// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"math/big"
	"testing"
)

// TestStrictEncodingsTable calls strictEncodings on its own, at the boundaries of rules 2 to 4. crypto/ed25519
// refuses most of these bytes too, so the vector replay alone cannot show the check makes them. Every row is
// built from integers written here, not from strict.go's constants, so the test also pins L and p. The
// TypeScript and Java SDKs carry the same rows.
func TestStrictEncodingsTable(t *testing.T) {
	rows := strictRows()
	if len(rows) != 35 {
		t.Fatalf("%d rows, want 35", len(rows))
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := strictEncodings(row.a, row.sig); got != row.want {
				t.Fatalf("strictEncodings = %v, want %v", got, row.want)
			}
		})
	}
}

type strictRow struct {
	name   string
	a, sig []byte
	want   bool
}

func strictRows() []strictRow {
	two := big.NewInt(2)
	pow2 := func(e int64) *big.Int { return new(big.Int).Exp(two, big.NewInt(e), nil) }
	dec := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			panic("not a decimal: " + s)
		}
		return n
	}
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) }
	one := big.NewInt(1)

	l := new(big.Int).Add(pow2(252), dec("27742317777372353535851937790883648493"))
	p := sub(pow2(255), big.NewInt(19))
	y8 := dec("55188659117513257062467267217118295137698188065244968500265048394206261417927")
	mid := pow2(254) // a y that no rule refuses, for the point a row is not about

	fine := encodePoint(mid, 0)
	rows := []strictRow{
		{"S = L - 1", fine, strictSignature(fine, sub(l, one)), true},
		{"S = L", fine, strictSignature(fine, l), false},
		{"S with bit 255 set", fine, strictSignature(fine, new(big.Int).SetBit(big.NewInt(1), 255, 1)), false},
	}
	for _, sign := range []uint{0, 1} {
		y := sub(p, two)
		rows = append(rows,
			strictRow{"R with y = p - 2, sign " + digit(sign), fine, strictSignature(encodePoint(y, sign), one), true},
			strictRow{"A with y = p - 2, sign " + digit(sign), encodePoint(y, sign), strictSignature(fine, one), true})
	}
	for _, c := range []struct {
		label string
		y     *big.Int
	}{{"p", p}, {"2^255 - 1", sub(pow2(255), one)}} {
		rows = append(rows,
			strictRow{"R with y = " + c.label, fine, strictSignature(encodePoint(c.y, 0), one), false},
			strictRow{"A with y = " + c.label, encodePoint(c.y, 0), strictSignature(fine, one), false})
	}
	for _, c := range []struct {
		label string
		y     *big.Int
	}{{"0", big.NewInt(0)}, {"1", one}, {"p - 1", sub(p, one)}, {"y8", y8}, {"p - y8", sub(p, y8)}} {
		for _, sign := range []uint{0, 1} {
			rows = append(rows,
				strictRow{"R with y = " + c.label + ", sign " + digit(sign), fine, strictSignature(encodePoint(c.y, sign), one), false},
				strictRow{"A with y = " + c.label + ", sign " + digit(sign), encodePoint(c.y, sign), strictSignature(fine, one), false})
		}
	}
	sig := strictSignature(fine, one)
	return append(rows,
		strictRow{"a key of 31 bytes", fine[:31], sig, false},
		strictRow{"a key of 33 bytes", append(append([]byte{}, fine...), 0), sig, false},
		strictRow{"a signature of 63 bytes", fine, sig[:63], false},
		strictRow{"a signature of 65 bytes", fine, append(append([]byte{}, sig...), 0), false})
}

func digit(n uint) string { return string(rune('0' + n)) }

// le32 returns n as 32 little-endian bytes.
func le32(n *big.Int) []byte {
	out := make([]byte, 32)
	be := n.FillBytes(make([]byte, 32))
	for i := range out {
		out[i] = be[31-i]
	}
	return out
}

// encodePoint returns a point's encoding: y little-endian, the sign bit in the top bit of the last byte.
func encodePoint(y *big.Int, sign uint) []byte {
	return le32(new(big.Int).SetBit(new(big.Int).Set(y), 255, sign))
}

func strictSignature(r []byte, s *big.Int) []byte {
	return append(append([]byte{}, r...), le32(s)...)
}
