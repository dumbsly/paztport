// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// Status returns the status a server gives the session req opens, StatusAttested or StatusUnsafe, against
// its own root ownRoot (nil when the server has none) and keyring ownKeyring, its policy key ownPolicyKey,
// the client policy keys it pinned, and its clock's now. The session is attested only when all of these
// hold, and unsafe otherwise:
//
//   - the request has a client root, and the server a root of its own;
//   - the client root verifies under the request's policy key, and ownRoot under ownPolicyKey;
//   - the request's policy key is one of pinned;
//   - the request's keyring, with its window, verifies under its policy key (see Request.KeyringFile);
//   - at now, the client's root and keyring and the server's own are all current.
//
// With no pinned key every session is unsafe: anyone can make a policy key and sign a root and keyring with
// it. ownKeyring is judged by its window only, never its signature: the caller verified it under
// ownPolicyKey when it loaded it, and passes that keyring and no other. A server whose own root or keyring
// has expired therefore opens every new session unsafe, and goes on serving unattested callers rather than
// stopping. Status never panics.
func Status(req Request, ownRoot *policy.Root, ownKeyring policy.KeyringFile, ownPolicyKey string, pinned []string,
	now int64) string {
	if req.ClientRoot == nil || ownRoot == nil || !slices.Contains(pinned, req.ClientPolicyKey) {
		return StatusUnsafe
	}
	ring := req.KeyringFile()
	if !req.ClientRoot.Verifies(req.ClientPolicyKey) || !ring.Verifies(req.ClientPolicyKey) ||
		!ownRoot.Verifies(ownPolicyKey) || !req.ClientRoot.Current(now) || !ring.Current(now) ||
		!ownRoot.Current(now) || !ownKeyring.Current(now) {
		return StatusUnsafe
	}
	return StatusAttested
}
