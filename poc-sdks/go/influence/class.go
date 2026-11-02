// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

// Class is the kind of content an entry or a label describes, as its wire name.
type Class string

// The four classes.
const (
	// ThirdParty is content from outside the trust boundary, which may carry instructions: an issue
	// anyone can write, a web page.
	ThirdParty Class = "third-party"
	// Private is data that must not reach a public destination unless it belongs to the destination's
	// owner.
	Private Class = "private"
	// Public is content that is already public.
	Public Class = "public"
	// LocalUntrusted is content the client can't vouch for: a result that failed verification or came
	// from an unattested server, a local read from an unlabelled folder, a program's output. It counts as
	// untrusted.
	LocalUntrusted Class = "local-untrusted"
)

// ParseClass returns the class whose wire name is s, and whether there is one.
func ParseClass(s string) (Class, bool) {
	c := Class(s)
	return c, c.known()
}

// known reports whether c is one of the four classes. Any other Class is one a caller built by hand.
func (c Class) known() bool {
	switch c {
	case ThirdParty, Private, Public, LocalUntrusted:
		return true
	}
	return false
}

// untrusted reports whether content of class c counts as untrusted for the rules: ThirdParty and
// LocalUntrusted do, and so, failing closed, does a class that is not one of the four.
func (c Class) untrusted() bool {
	return c != Private && c != Public
}
