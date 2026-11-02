// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp_test

import (
	"bytes"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// FuzzReadChain reads any bytes as a chain. A read never panics and answers OK, CHAIN_MISSING or
// BAD_SIGNATURE, as its token does. A chain it reads is not empty, has signing bytes for every stamp and
// writes back as the same bytes, since wire bytes are canonical.
func FuzzReadChain(f *testing.F) {
	f.Add([]byte("[]"))
	f.Add([]byte(`[{"v":3}]`))
	for _, b := range seedChains(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, code := stamp.ParseChain(b)
		if _, tokCode := stamp.ReadChain(b64.Encode(b)); tokCode != code {
			t.Fatalf("ReadChain answered %s where ParseChain answered %s", tokCode, code)
		}
		switch code {
		case reason.ChainMissing, reason.BadSignature:
			if c != nil {
				t.Fatalf("a chain refused as %s came with stamps", code)
			}
			return
		case reason.OK:
		default:
			t.Fatalf("ParseChain answered %s", code)
		}
		if len(c) == 0 {
			t.Fatal("ParseChain read an empty chain")
		}
		for i, s := range c {
			if _, err := s.SigningBytes(); err != nil {
				t.Fatalf("stamp %d has no signing bytes: %v", i, err)
			}
		}
		back, err := c.Wire()
		if err != nil {
			t.Fatalf("Wire refused a chain ParseChain read: %v", err)
		}
		if !bytes.Equal(back, b) {
			t.Fatal("Wire wrote other bytes than ParseChain read")
		}
	})
}

// seedChains returns the wire bytes of the chains v3.json's verify cases carry.
func seedChains(f *testing.F) [][]byte {
	var out [][]byte
	vectors.Load(f, "v3.json").Get("verify").Each(func(_ string, c vectors.Node) {
		if b, err := b64.Decode(c.Get("chainToken").Str()); err == nil {
			out = append(out, b)
		}
	})
	return out
}
