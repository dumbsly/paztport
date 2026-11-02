// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
)

// TestVectorKeys reads every key v3.json lists, which V3Key derives from its name, and writes each back as
// the same text.
func TestVectorKeys(t *testing.T) {
	vectors.Load(t, "v3.json").Get("keys").Each(func(name string, k vectors.Node) {
		t.Run(name, func(t *testing.T) {
			k := k.With(t)
			priv, pub := vectors.V3Key(t, name)
			pubText, privText := k.Get("pub").Str(), k.Get("priv").Str()

			gotPub, err := keys.ParsePublic(pubText)
			if err != nil {
				t.Fatalf("ParsePublic refused it: %v", err)
			}
			if !bytes.Equal(gotPub, pub) {
				t.Fatalf("ParsePublic = %x, want %x", gotPub, pub)
			}
			if got := keys.EncodePublic(pub); got != pubText {
				t.Fatalf("EncodePublic = %s, want %s", got, pubText)
			}

			gotPriv, err := keys.ParsePrivate(privText)
			if err != nil {
				t.Fatalf("ParsePrivate refused it: %v", err)
			}
			if !bytes.Equal(gotPriv, priv) {
				t.Fatal("ParsePrivate gave another key")
			}
			if got := keys.EncodePrivate(priv); got != privText {
				t.Fatalf("EncodePrivate = %s, want %s", got, privText)
			}
		})
	})
}

// TestParseRefuses holds the readers to the spec's exact layouts: a 44-byte SPKI and a 48-byte PKCS#8, each
// opening with its fixed prefix, as canonical base64url.
func TestParseRefuses(t *testing.T) {
	k := vectors.Load(t, "v3.json").Get("keys").Get("pi")
	spki := decode(t, k.Get("pub").Str())
	pkcs8 := decode(t, k.Get("priv").Str())

	for _, c := range []struct {
		name string
		der  []byte
	}{
		{"43 bytes", spki[:43]},
		{"45 bytes", append(clone(spki), 0)},
		{"the prefix alone", spki[:12]},
		{"no bytes", nil},
		{"the X448 algorithm", with(spki, 8, 0x71)},
		{"a bit string with unused bits", with(spki, 11, 0x01)},
		{"a longer outer length", with(spki, 1, 0x2b)},
		{"a private key", pkcs8},
	} {
		t.Run("public/"+c.name, func(t *testing.T) {
			if got, err := keys.ParsePublic(b64.Encode(c.der)); err == nil {
				t.Fatalf("ParsePublic accepted it as %x", got)
			}
		})
	}
	for _, c := range []struct {
		name string
		der  []byte
	}{
		{"47 bytes", pkcs8[:47]},
		{"49 bytes", append(clone(pkcs8), 0)},
		{"version 1", with(pkcs8, 4, 0x01)},
		{"the X448 algorithm", with(pkcs8, 11, 0x71)},
		{"a 33-byte inner octet string", with(pkcs8, 15, 0x21)},
		{"no bytes", nil},
		{"a public key", spki},
	} {
		t.Run("private/"+c.name, func(t *testing.T) {
			if _, err := keys.ParsePrivate(b64.Encode(c.der)); err == nil {
				t.Fatal("ParsePrivate accepted it")
			}
		})
	}
	for _, c := range []struct{ name, text string }{
		{"padded", k.Get("pub").Str() + "="},
		{"a trailing newline", k.Get("pub").Str() + "\n"},
		{"a character of the standard alphabet", "+" + k.Get("pub").Str()[1:]},
	} {
		t.Run("text/"+c.name, func(t *testing.T) {
			if _, err := keys.ParsePublic(c.text); err == nil {
				t.Fatal("ParsePublic accepted text that is not canonical base64url")
			}
		})
	}
}

// TestRefusalNamesNoKey checks that a refusal does not quote the text it refused.
func TestRefusalNamesNoKey(t *testing.T) {
	text := b64.Encode(bytes.Repeat([]byte{0xab}, 48))
	if _, err := keys.ParsePrivate(text); err == nil || strings.Contains(err.Error(), text) {
		t.Fatalf("ParsePrivate = %v, want a refusal that does not quote the key", err)
	}
}

// TestLoad reads key files, trimming the whitespace around the one value each holds.
func TestLoad(t *testing.T) {
	k := vectors.Load(t, "v3.json").Get("keys").Get("pi")
	priv, _ := vectors.V3Key(t, "pi")
	dir := t.TempDir()
	keyFile := write(t, dir, "pi.key", "\r\n\t "+k.Get("priv").Str()+"\r\n\t ")
	pinFile := write(t, dir, "policy.pub", " "+k.Get("pub").Str()+"\n")

	got, err := keys.LoadPrivate(keyFile)
	if err != nil {
		t.Fatalf("LoadPrivate: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Fatal("LoadPrivate gave another key")
	}
	pin, err := keys.LoadPin(pinFile)
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}
	if pin != k.Get("pub").Str() {
		t.Fatalf("LoadPin = %q, want the trimmed text", pin)
	}

	// Only space, tab, line feed and carriage return are trimmed: a key beside any other whitespace, such as
	// a vertical tab or U+00A0, is refused, and a pin keeps it.
	for name, around := range map[string]string{
		"a vertical tab": "\x0b",
		"a form feed":    "\x0c",
		"U+00A0":         "\xc2\xa0",
		"U+0085":         "\xc2\x85",
		"U+3000":         "\xe3\x80\x80",
	} {
		file := write(t, dir, "around.key", around+k.Get("priv").Str()+around)
		if _, err := keys.LoadPrivate(file); err == nil {
			t.Errorf("LoadPrivate read a key surrounded by %s", name)
		}
		pinText := around + k.Get("pub").Str() + "\n"
		if pin, err := keys.LoadPin(write(t, dir, "around.pub", pinText)); err != nil || pin != pinText[:len(pinText)-1] {
			t.Errorf("LoadPin = %+q, %v; want the text with %s kept", pin, err, name)
		}
	}

	// A pin is text, not decoded: whatever the file holds, trimmed, is the pin.
	if pin, err := keys.LoadPin(write(t, dir, "odd.pub", "  not a key \n")); err != nil || pin != "not a key" {
		t.Fatalf("LoadPin = %q, %v; want the trimmed text", pin, err)
	}

	bad := write(t, dir, "bad.key", k.Get("pub").Str())
	if _, err := keys.LoadPrivate(bad); err == nil {
		t.Fatal("LoadPrivate read a public key as a private one")
	} else if !strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), k.Get("pub").Str()) {
		t.Fatalf("LoadPrivate = %v, want a refusal naming the file and not quoting it", err)
	}

	missing := filepath.Join(dir, "missing.key")
	if _, err := keys.LoadPrivate(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadPrivate of a missing file = %v, want fs.ErrNotExist", err)
	}
	if _, err := keys.LoadPin(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadPin of a missing file = %v, want fs.ErrNotExist", err)
	}
}

// TestSignVerify signs and verifies, and refuses keys and signatures of the wrong length, where ed25519's own
// functions would panic, without panicking.
func TestSignVerify(t *testing.T) {
	priv, pub := vectors.V3Key(t, "pi")
	msg := []byte("paztport")
	sig, err := keys.Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(sig, ed25519.Sign(priv, msg)) {
		t.Fatal("Sign gave another signature than ed25519.Sign")
	}
	if !keys.Verify(pub, msg, sig) {
		t.Fatal("Verify refused a good signature")
	}
	if keys.Verify(pub, []byte("paztporT"), sig) {
		t.Error("Verify accepted a signature over another message")
	}
	for _, key := range []ed25519.PublicKey{nil, pub[:31], append(bytes.Clone(pub), 0)} {
		if keys.Verify(key, msg, sig) {
			t.Errorf("Verify accepted a %d-byte key", len(key))
		}
	}
	for _, s := range [][]byte{nil, sig[:63], append(bytes.Clone(sig), 0)} {
		if keys.Verify(pub, msg, s) {
			t.Errorf("Verify accepted a %d-byte signature", len(s))
		}
	}
	for _, key := range []ed25519.PrivateKey{nil, priv[:63], priv.Seed()} {
		if s, err := keys.Sign(key, msg); err == nil {
			t.Errorf("Sign signed with a %d-byte key: %x", len(key), s)
		}
	}
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.Decode(s)
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	return b
}

func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}

// with returns a copy of b whose byte i is c.
func with(b []byte, i int, c byte) []byte {
	b = clone(b)
	b[i] = c
	return b
}

func write(t *testing.T, dir, name, text string) string {
	t.Helper()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}
