// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"fmt"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// Requirement is what a client requires of a server (sessions.md, A client that requires extensions): the
// extensions the server must act on, each once and sorted, and whether the client goes on without them, the
// configuration switch. The zero Requirement requires nothing. Its fields are unexported, so a requirement is
// built by NewRequirement, which checks its names once, and cannot change after it is built.
type Requirement struct {
	extensions      []string // sorted, none twice, each an extension name
	continueWithout bool
}

// NewRequirement returns the requirement of extensions, each held once and sorted (by UTF-16 code units, which
// for extension names is byte order), with the switch continueWithout. It refuses a name that is not an
// extension name, so that a bad configuration fails where it is read, not at the first call's stamp. It copies
// what it is given.
func NewRequirement(extensions []string, continueWithout bool) (Requirement, error) {
	names := slices.Clone(extensions)
	for _, name := range names {
		if !stamp.IsExtensionName(name) {
			return Requirement{}, fmt.Errorf("paztport session: a client can't require %q: not an extension name",
				name)
		}
	}
	slices.Sort(names)
	return Requirement{extensions: slices.Compact(names), continueWithout: continueWithout}, nil
}

// Extensions returns the extensions r requires, sorted, each once: a copy, empty for none.
func (r Requirement) Extensions() []string {
	return append([]string{}, r.extensions...)
}

// ContinueWithout reports whether the client makes calls though the server does not give it what r requires.
func (r Requirement) ContinueWithout() bool {
	return r.continueWithout
}

// Calls is what a client may do in the session a handshake left it: whether it makes calls at all, and the
// names each call's block requires (wire.md, Blocks).
type Calls struct {
	// Calls reports whether the client makes calls in the session.
	Calls bool
	// Requires lists the names each call's block requires, sorted; empty, never nil, for none.
	Requires []string
}

// CallsAfter returns what a client with r may do in the session a handshake left it (sessions.md, "A client
// that requires extensions"). check is the first reply's outcome, "" when no reply could be checked (an
// error, a timeout, no answer); a client that sent no handshake passes Unsafe. listed is that reply's
// Extensions, empty when it did not read.
//
// Only an attested session whose reply lists every required name lets a client make calls under its
// requirement, so neither a server answering "unsafe" nor anyone who can make the handshake fail switches it
// off; only the switch does, and then a call carries no requires for a name the client could not get.
func (r Requirement) CallsAfter(check Check, listed []string) Calls {
	if len(r.extensions) == 0 {
		return Calls{Calls: true, Requires: []string{}}
	}
	required := r.Extensions()
	if check == Attested {
		return Calls{Calls: true, Requires: required}
	}
	if !r.continueWithout {
		return Calls{Calls: false, Requires: []string{}}
	}
	if check == ExtensionRequired {
		return Calls{Calls: true, Requires: slices.DeleteFunc(required, func(name string) bool {
			return !slices.Contains(listed, name)
		})}
	}
	return Calls{Calls: true, Requires: []string{}}
}
