// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package vectors reads the conformance vector files in poc-sdks/spec/vectors for the module's tests. Only
// tests import it.
//
// A vector file is ordinary JSON describing cases; the bytes a case hands to the SDK are a member's text
// (a token, a file, hex), never a value this package has read. So the package may walk the files with
// encoding/json while the SDK reads with its own reader. It walks them in order: a Node keeps an object's
// members in the order the file gives them and each value's exact text, and never goes through a Go map.
//
// Strings are decoded here, not by encoding/json, which writes U+FFFD for an escaped lone surrogate. Str
// turns an unpaired \uD800–\uDFFF escape into the three bytes UTF-8's pattern gives it (WTF-8: \ud800 is
// ED A0 80), the Go string that stands for text with no UTF-8 form. An escaped pair is the one character.
//
// A Node fails the test it reports to when it is read as something it is not: Get of a member it lacks,
// Int of a number that is not an integer, Str of an object. Has asks whether an object has a member, and
// IsNull whether a value is null, without failing. A Node reports to the test that loaded it, so a subtest
// rebinds it with With first:
//
//	vectors.Load(t, "json.json").Get("base64url").Each(func(name string, c vectors.Node) {
//		t.Run(name, func(t *testing.T) {
//			c := c.With(t)
//			got, err := b64.Decode(c.Get("text").Str())
//			if c.Get("expected").IsNull() && err == nil {
//				t.Fatalf("Decode accepted it as %x", got)
//			}
//		})
//	})
//
// The package imports only the standard library, so any package's own tests may import it.
package vectors
