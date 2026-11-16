// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// settings returns a service's extension settings, stated once (verification.md, Inputs: actsOn and
// allowedExtensions are the service's configuration whether or not it has a verifier): v's where there is a
// verifier, else given. Beside a verifier, given must be the zero value, which states nothing, or equal to the
// verifier's; otherwise it panics, naming what holds them, since a service that verified under one actsOn and
// matched blocks, built its own or handed items on under another would be a fault in the program.
func settings(v *verify.Verifier, given verify.Extensions, what string) verify.Extensions {
	if v == nil {
		return given
	}
	own := v.Extensions()
	if !given.Equal(verify.Extensions{}) && !given.Equal(own) {
		panic(fmt.Sprintf("paztport http: the %s's Extensions differ from its Verifier's; state them once", what))
	}
	return own
}
