// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// Kind is the kind of JSON value a Node holds.
type Kind int

// The kinds of JSON value.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// String returns the kind's name, as a failure message gives it.
func (k Kind) String() string {
	switch k {
	case Null:
		return "null"
	case Bool:
		return "a boolean"
	case Number:
		return "a number"
	case String:
		return "a string"
	case Array:
		return "an array"
	case Object:
		return "an object"
	}
	return "Kind(" + strconv.Itoa(int(k)) + ")"
}

// Node is one value in a vector file, with the test it reports failures to. Nodes come from Load; the
// zero Node is not one.
type Node struct {
	t testing.TB
	v *value
}

// value is a read value. Values are shared between Nodes and never change once read.
type value struct {
	path  string // where the value sits, for failure messages, such as json.json.base64url[3].text
	raw   []byte // the value's exact text in the file
	kind  Kind
	names []string // an object's member names, in file order
	kids  []*value // an object's member values or an array's items, in file order
}

// Load returns the root of vector file file (such as "v3.json"), found in the poc-sdks/spec/vectors
// directory at or above the working directory. It fails t if the file cannot be read, is not JSON, or
// repeats a member name in an object.
func Load(t testing.TB, file string) Node {
	t.Helper()
	v, err := tree(file)
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	return Node{t, v}
}

var (
	treesMu sync.Mutex
	trees   = map[string]*value{} // each file read once per test binary
)

func tree(file string) (*value, error) {
	treesMu.Lock()
	defer treesMu.Unlock()
	if v, ok := trees[file]; ok {
		return v, nil
	}
	dir, err := directory()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return nil, err
	}
	v, err := parse(file, b)
	if err != nil {
		return nil, err
	}
	trees[file] = v
	return v, nil
}

// directory returns poc-sdks/spec/vectors in the nearest directory at or above the working directory that
// holds one.
func directory() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "poc-sdks", "spec", "vectors")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
		up := filepath.Dir(dir)
		if up == dir {
			return "", errors.New("no poc-sdks/spec/vectors at or above the working directory")
		}
		dir = up
	}
}

// With returns n reporting its failures to t. A subtest calls it on the Nodes it reads, because a Node
// fails the test that loaded it, and a subtest must not stop its parent.
func (n Node) With(t testing.TB) Node {
	return Node{t, n.v}
}

// Kind returns the kind of value n holds.
func (n Node) Kind() Kind {
	return n.v.kind
}

// Raw returns n's exact text in the file: for an object member, the text after the colon, without the
// whitespace around it.
func (n Node) Raw() []byte {
	return slices.Clone(n.v.raw)
}

// Has reports whether object n has a member called name. It fails the test if n is not an object.
func (n Node) Has(name string) bool {
	n.t.Helper()
	n.want(Object)
	return slices.Contains(n.v.names, name)
}

// Get returns the member of object n called name. It fails the test if n is not an object or has no such
// member; Has asks first, without failing when the member is absent.
func (n Node) Get(name string) Node {
	n.t.Helper()
	n.want(Object)
	i := slices.Index(n.v.names, name)
	if i < 0 {
		n.t.Fatalf("vectors: %s has no member %q", n.v.path, name)
	}
	return n.kid(i)
}

// Names returns the member names of object n, in the order the file gives them. It fails the test if n
// is not an object.
func (n Node) Names() []string {
	n.t.Helper()
	n.want(Object)
	return slices.Clone(n.v.names)
}

// Index returns item i of array n. It fails the test if n is not an array or has no item i.
func (n Node) Index(i int) Node {
	n.t.Helper()
	n.want(Array)
	if i < 0 || i >= len(n.v.kids) {
		n.t.Fatalf("vectors: %s has %d items, so no item %d", n.v.path, len(n.v.kids), i)
	}
	return n.kid(i)
}

// Len returns the number of items of array n or members of object n. It fails the test if n is neither.
func (n Node) Len() int {
	n.t.Helper()
	if n.v.kind != Array && n.v.kind != Object {
		n.t.Fatalf("vectors: %s is %v, not an array or an object", n.v.path, n.v.kind)
	}
	return len(n.v.kids)
}

// Each calls f for each member of object n with its name, or for each item of array n, in file order.
// An item's name is its own "name" member when it is an object holding a string of that name, as a case
// is, and its index otherwise, so f can pass the name to t.Run. Each fails the test if n is neither.
func (n Node) Each(f func(name string, n Node)) {
	n.t.Helper()
	switch n.v.kind {
	case Object:
		for i, name := range n.v.names {
			f(name, n.kid(i))
		}
	case Array:
		for i := range n.v.kids {
			item := n.kid(i)
			f(item.caseName(i), item)
		}
	default:
		n.t.Fatalf("vectors: %s is %v, not an array or an object", n.v.path, n.v.kind)
	}
}

func (n Node) caseName(i int) string {
	if n.v.kind == Object {
		if j := slices.Index(n.v.names, "name"); j >= 0 && n.v.kids[j].kind == String {
			return unquote(n.v.kids[j].raw)
		}
	}
	return strconv.Itoa(i)
}

// Str returns the text of string n, with an escaped lone surrogate as its WTF-8 bytes (see the package
// documentation). It fails the test if n is not a string.
func (n Node) Str() string {
	n.t.Helper()
	n.want(String)
	return unquote(n.v.raw)
}

// Int returns the value of number n. It fails the test if n is not a number, or is one written with a
// fraction or an exponent, such as 1.5 or 1798761600000.0, or does not fit an int64.
func (n Node) Int() int64 {
	n.t.Helper()
	n.want(Number)
	i, err := strconv.ParseInt(string(n.v.raw), 10, 64)
	if err != nil {
		n.t.Fatalf("vectors: %s is %s, not an int64", n.v.path, n.v.raw)
	}
	return i
}

// Bool returns the value of boolean n. It fails the test if n is not a boolean.
func (n Node) Bool() bool {
	n.t.Helper()
	n.want(Bool)
	return n.v.raw[0] == 't'
}

// IsNull reports whether n is null.
func (n Node) IsNull() bool {
	return n.v.kind == Null
}

func (n Node) kid(i int) Node {
	return Node{n.t, n.v.kids[i]}
}

func (n Node) want(k Kind) {
	n.t.Helper()
	if n.v.kind != k {
		n.t.Fatalf("vectors: %s is %v, not %v", n.v.path, n.v.kind, k)
	}
}

// parse reads b, the text of the file called file, as one JSON value.
func parse(file string, b []byte) (*value, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	p := parser{d: d, text: b}
	v, err := p.value(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: text after the value", file)
	}
	return v, nil
}

// parser walks a file's tokens with encoding/json, which checks the grammar, and cuts each value's text
// out of the file by the decoder's offsets.
type parser struct {
	d    *json.Decoder
	text []byte
}

// start returns the offset of the next token: the decoder's offset is the end of the last token, before
// any whitespace, comma or colon that separates it from the next.
func (p *parser) start() int64 {
	i := p.d.InputOffset()
	for i < int64(len(p.text)) && strings.IndexByte(" \t\r\n,:", p.text[i]) >= 0 {
		i++
	}
	return i
}

func (p *parser) value(path string) (*value, error) {
	from := p.start()
	tok, err := p.d.Token()
	if err != nil {
		return nil, err
	}
	v := &value{path: path}
	switch tok := tok.(type) {
	case json.Delim:
		if tok == '{' {
			v.kind = Object
			if err := p.members(v); err != nil {
				return nil, err
			}
		} else {
			v.kind = Array
			for i := 0; p.d.More(); i++ {
				item, err := p.value(path + "[" + strconv.Itoa(i) + "]")
				if err != nil {
					return nil, err
				}
				v.kids = append(v.kids, item)
			}
		}
		if _, err := p.d.Token(); err != nil { // the closing delimiter
			return nil, err
		}
	case string:
		v.kind = String
	case json.Number:
		v.kind = Number
	case bool:
		v.kind = Bool
	case nil:
		v.kind = Null
	}
	v.raw = p.text[from:p.d.InputOffset()]
	return v, nil
}

func (p *parser) members(v *value) error {
	for p.d.More() {
		from := p.start()
		if _, err := p.d.Token(); err != nil {
			return err
		}
		name := unquote(p.text[from:p.d.InputOffset()])
		if slices.Contains(v.names, name) {
			return fmt.Errorf("%s repeats the member name %q", v.path, name)
		}
		kid, err := p.value(v.path + "." + name)
		if err != nil {
			return err
		}
		v.names = append(v.names, name)
		v.kids = append(v.kids, kid)
	}
	return nil
}

// unquote decodes lit, a JSON string literal whose grammar the decoder has checked. An escaped surrogate
// that is not half of an escaped pair becomes its WTF-8 bytes.
func unquote(lit []byte) string {
	s := lit[1 : len(lit)-1]
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			out = append(out, s[i])
			i++
			continue
		}
		if s[i+1] != 'u' {
			out = append(out, escapes[s[i+1]])
			i += 2
			continue
		}
		r := hex4(s[i+2 : i+6])
		i += 6
		if 0xD800 <= r && r < 0xDC00 && i+6 <= len(s) && s[i] == '\\' && s[i+1] == 'u' {
			if low := hex4(s[i+2 : i+6]); 0xDC00 <= low && low <= 0xDFFF {
				out = utf8.AppendRune(out, utf16.DecodeRune(r, low))
				i += 6
				continue
			}
		}
		if utf16.IsSurrogate(r) {
			out = append(out, 0xE0|byte(r>>12), 0x80|byte(r>>6)&0x3F, 0x80|byte(r)&0x3F)
			continue
		}
		out = utf8.AppendRune(out, r)
	}
	return string(out)
}

// escapes maps the character after a backslash to the one it stands for, \u aside.
var escapes = [256]byte{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

func hex4(h []byte) rune {
	r, _ := strconv.ParseUint(string(h), 16, 16) // the decoder checked the four hex digits
	return rune(r)
}

// The fixed DER prefixes of an Ed25519 private key as PKCS#8 and a public key as SPKI, before the 32 bytes.
const (
	pkcs8Prefix = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"
	spkiPrefix  = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"
)

// keyFiles are the vector files with a keys section.
var keyFiles = []string{"v3.json", "events.json", "http-v3.json"}

// V3Key returns the vector key called name, derived by v3.json's rule: its seed is
// SHA-256("paztport-v3-vector-key:" + name). It fails the test unless some vector file's keys lists name,
// and every file that lists it gives this key's priv (PKCS#8) and pub (SPKI) as base64url.
func V3Key(t testing.TB, name string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	priv, pub, wantPriv, wantPub := derivedKey(name)
	listed := false
	for _, file := range keyFiles {
		keys := Load(t, file).Get("keys")
		if !keys.Has(name) {
			continue
		}
		listed = true
		key := keys.Get(name)
		if key.Get("priv").Str() != wantPriv || key.Get("pub").Str() != wantPub {
			t.Fatalf("vectors: %s gives key %q other than v3.json's rule derives", file, name)
		}
	}
	if !listed {
		t.Fatalf("vectors: no vector file lists the key %q", name)
	}
	return priv, pub
}

// derivedKey returns the vector key called name, derived by v3.json's rule, and its priv (PKCS#8) and pub
// (SPKI) as a keys section gives them, in base64url.
func derivedKey(name string) (priv ed25519.PrivateKey, pub ed25519.PublicKey, privText, pubText string) {
	seed := sha256.Sum256([]byte("paztport-v3-vector-key:" + name))
	priv = ed25519.NewKeyFromSeed(seed[:])
	pub = priv.Public().(ed25519.PublicKey)
	privText = base64.RawURLEncoding.EncodeToString([]byte(pkcs8Prefix + string(seed[:])))
	pubText = base64.RawURLEncoding.EncodeToString([]byte(spkiPrefix + string(pub)))
	return priv, pub, privText, pubText
}
