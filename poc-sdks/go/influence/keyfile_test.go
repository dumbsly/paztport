// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package influence_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
)

// TestLoadBoundaryKey reads boundary.key files: 32 bytes as canonical base64url, with only the space, tab,
// line feed and carriage return around the text trimmed.
func TestLoadBoundaryKey(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0xA5}, influence.KeyLength)
	key[0], key[31] = 0x00, 0xFF
	text := b64.Encode(key)
	// 32 bytes in the standard alphabet: the right length, refused for its alphabet alone.
	std := strings.NewReplacer("-", "+", "_", "/").Replace(b64.Encode(bytes.Repeat([]byte{0xFB, 0xFF}, 16)))
	if !strings.ContainsAny(std, "+/") || len(std) != 43 {
		t.Fatalf("the standard-alphabet text %q does not test the alphabet", std)
	}

	for name, around := range map[string]string{
		"nothing":           "",
		"a space":           " ",
		"a tab":             "\t",
		"a line feed":       "\n",
		"a carriage return": "\r",
		"all four":          " \t\r\n",
	} {
		got, err := influence.LoadBoundaryKey(writeFile(t, dir, "boundary.key", around+text+around))
		if err != nil {
			t.Errorf("LoadBoundaryKey with %s around the key: %v", name, err)
			continue
		}
		if !bytes.Equal(got, key) {
			t.Errorf("LoadBoundaryKey with %s around the key gave another key", name)
		}
	}

	// Anything else around the text, or text that is not canonical base64url of 32 bytes, is refused, with a
	// refusal that names the file and never quotes it.
	for name, contents := range map[string]string{
		"a no-break space before":   "\xc2\xa0" + text,
		"a no-break space after":    text + "\xc2\xa0",
		"a vertical tab around":     "\x0b" + text + "\x0b",
		"a form feed around":        "\x0c" + text + "\x0c",
		"a byte order mark before":  "\xef\xbb\xbf" + text,
		"padding":                   text + "=",
		"the standard alphabet":     std,
		"31 bytes":                  b64.Encode(key[:31]),
		"33 bytes":                  b64.Encode(append(bytes.Clone(key), 0)),
		"an empty file":             "",
		"whitespace alone":          " \n",
		"a space inside":            text[:20] + " " + text[20:],
		"non-zero unused bits":      text[:len(text)-1] + "x",
		"two keys on two lines":     text + "\n" + text,
		"the key in quotes":         `"` + text + `"`,
		"a JSON object holding one": `{"key":"` + text + `"}`,
	} {
		path := writeFile(t, dir, "bad.key", contents)
		got, err := influence.LoadBoundaryKey(path)
		if err == nil {
			t.Errorf("LoadBoundaryKey read %s as %x", name, got)
			continue
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, "paztport influence: ") || !strings.Contains(msg, path) {
			t.Errorf("LoadBoundaryKey of %s = %q, want the package's prefix and the file's name", name, msg)
		}
		if strings.Contains(msg, text[:8]) {
			t.Errorf("LoadBoundaryKey of %s = %q quotes the file", name, msg)
		}
	}

	missing := filepath.Join(dir, "missing.key")
	if _, err := influence.LoadBoundaryKey(missing); !errors.Is(err, fs.ErrNotExist) ||
		!strings.HasPrefix(err.Error(), "paztport influence: can't read the boundary key file: ") {
		t.Fatalf("LoadBoundaryKey of a missing file = %v, want the package's prefix and fs.ErrNotExist", err)
	}
}

// writeFile writes contents to name in dir and returns its path.
func writeFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}
