// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
)

// keyFileSpace is what a key file's reader trims from around its value: JSON's whitespace (RFC 8259),
// space, horizontal tab, line feed and carriage return, and nothing else, as the keys package trims.
const keyFileSpace = " \t\n\r"

// LoadBoundaryKey reads an egress's boundary key file, boundary.key: KeyLength bytes as canonical
// base64url, with the space, tab, line feed and carriage return around the text trimmed and nothing
// else, so a key beside a no-break space or a byte order mark is refused. A key of any other length is
// refused, never stretched or cut. A refusal names the file and never quotes it.
//
// The key belongs to one egress service and its replicas and never leaves the sender: see Reduce.
func LoadBoundaryKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("paztport influence: can't read the boundary key file: %w", err)
	}
	key, err := b64.Decode(strings.Trim(string(b), keyFileSpace))
	if err != nil || len(key) != KeyLength {
		return nil, errors.New("paztport influence: " + path + ": not the base64url of a 32-byte boundary key")
	}
	return key, nil
}
