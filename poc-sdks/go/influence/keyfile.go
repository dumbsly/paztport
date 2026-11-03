// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence

import (
	"errors"
	"fmt"
	"os"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

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
	key, err := b64.Decode(text.TrimFileSpace(string(b)))
	if err != nil || len(key) != KeyLength {
		return nil, errors.New("paztport influence: " + path + ": not the base64url of a 32-byte boundary key")
	}
	return key, nil
}
