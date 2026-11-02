// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"bytes"
	"strconv"
	"unicode/utf8"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

// The limits. A value at a limit is read, and one past it refused.
const (
	// WireBytes is the most bytes an object's wire bytes may hold.
	WireBytes = 262144
	// TokenText is the most characters a token may hold: the unpadded base64url length of WireBytes bytes.
	TokenText = 349526
	// FileBytes is the most bytes a file may hold.
	FileBytes = 1048576
	// MaxDepth is the deepest a value may nest. An array or object is one level and each one inside it one
	// more, so [] is one level and [[]] two.
	MaxDepth = 32
)

// ReadWire reads wire bytes: b is within WireBytes, parses as one value, and is exactly that value's
// canonical bytes.
func ReadWire(b []byte) (Value, error) {
	if len(b) > WireBytes {
		return Value{}, refuse(StepSize, "the wire bytes are over the "+strconv.Itoa(WireBytes)+"-byte limit")
	}
	v, err := parse(b)
	if err != nil {
		return Value{}, err
	}
	// parse admits nothing Wire refuses, and canonical bytes are never longer than the text they were
	// read from, so Wire does not fail here; if it did, b would not be canonical bytes.
	canonical, err := Wire(v)
	if err != nil {
		return Value{}, refuse(StepCanonical, "the value has no canonical bytes")
	}
	if !bytes.Equal(canonical, b) {
		return Value{}, refuseFrom(StepCanonical, "not the canonical bytes", canonical, b)
	}
	return v, nil
}

// ReadToken reads a token, the base64url of wire bytes: s is within TokenText characters, is canonical
// base64url, and its bytes read by ReadWire. Text that does not decode is refused at the parse step.
func ReadToken(s string) (Value, error) {
	if len(s) > TokenText {
		return Value{}, refuse(StepSize, "the token is over the "+strconv.Itoa(TokenText)+"-character limit")
	}
	b, err := b64.Decode(s)
	if err != nil {
		return Value{}, refuse(StepParse, "the token is not canonical base64url")
	}
	return ReadWire(b)
}

// ReadFile reads a file: b is within FileBytes and parses as one value. A file's members may come in any
// order, with any JSON whitespace and any escape RFC 8259 defines.
func ReadFile(b []byte) (Value, error) {
	if len(b) > FileBytes {
		return Value{}, refuse(StepSize, "the file is over the "+strconv.Itoa(FileBytes)+"-byte limit")
	}
	return parse(b)
}

// refuseFrom returns the refusal of rule at step, from the first offset at which a and b differ.
func refuseFrom(step Step, rule string, a, b []byte) *Error {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return &Error{Step: step, msg: rule + ", from byte " + strconv.Itoa(i)}
}

// parse reads b as one JSON text (RFC 8259 §2: ws value ws), held to the protocol's rules.
func parse(b []byte) (Value, error) {
	if bytes.HasPrefix(b, []byte("\xEF\xBB\xBF")) {
		return Value{}, refuseAt(StepParse, "a byte order mark", 0)
	}
	p := parser{b: b}
	p.space()
	v, err := p.value()
	if err != nil {
		return Value{}, err
	}
	p.space()
	if p.i < len(b) {
		return Value{}, p.refuse("text after the value")
	}
	return v, nil
}

// parser reads JSON text from b, which it never changes. Its methods return a refusal at the first
// byte that breaks a rule.
type parser struct {
	b     []byte
	i     int // the offset of the next byte
	depth int // the containers open around the next byte
}

func (p *parser) refuse(rule string) *Error {
	return refuseAt(StepParse, rule, p.i)
}

// next returns the byte at the offset, or 0 at the end; 0 is never valid where next is asked.
func (p *parser) next() byte {
	if p.i < len(p.b) {
		return p.b[p.i]
	}
	return 0
}

// space skips the four whitespace characters RFC 8259 §2 allows.
func (p *parser) space() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// value reads the value at the offset.
func (p *parser) value() (Value, error) {
	switch c := p.next(); {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.string()
		if err != nil {
			return Value{}, err
		}
		return S(s), nil
	case c == '-':
		// A protocol integer has no sign, so a minus sign is refused before any digit is read.
		return Value{}, p.refuse("a negative number")
	case '0' <= c && c <= '9':
		return p.integer()
	case p.literal("true"):
		return B(true), nil
	case p.literal("false"):
		return B(false), nil
	case p.literal("null"):
		return Null(), nil
	}
	return Value{}, p.refuse("no value")
}

// literal reads word if the text at the offset is word, and reports whether it was.
func (p *parser) literal(word string) bool {
	if !bytes.HasPrefix(p.b[p.i:], []byte(word)) {
		return false
	}
	p.i += len(word)
	return true
}

// open enters the container whose bracket is at the offset, refusing it before anything inside it is
// read if it would nest deeper than MaxDepth.
func (p *parser) open() error {
	if p.depth == MaxDepth {
		return p.refuse("nesting deeper than " + strconv.Itoa(MaxDepth))
	}
	p.depth++
	p.i++
	p.space()
	return nil
}

// object reads the object whose opening brace is at the offset, its members in the order read.
func (p *parser) object() (Value, error) {
	if err := p.open(); err != nil {
		return Value{}, err
	}
	defer func() { p.depth-- }()
	if p.next() == '}' {
		p.i++
		return Value{kind: KindObject}, nil
	}
	var members []Member
	seen := map[string]struct{}{}
	for {
		if p.next() != '"' {
			return Value{}, p.refuse("expected a member name")
		}
		at := p.i
		name, err := p.string()
		if err != nil {
			return Value{}, err
		}
		// RFC 7493 §2.3, comparing names as read, after their escapes.
		if _, ok := seen[name]; ok {
			return Value{}, refuseAt(StepParse, "a repeated member name", at)
		}
		seen[name] = struct{}{}
		p.space()
		if p.next() != ':' {
			return Value{}, p.refuse("expected ':'")
		}
		p.i++
		p.space()
		v, err := p.value()
		if err != nil {
			return Value{}, err
		}
		members = append(members, Member{Name: name, Value: v})
		p.space()
		switch p.next() {
		case ',':
			p.i++
			p.space()
		case '}':
			p.i++
			return Value{kind: KindObject, members: members}, nil
		default:
			return Value{}, p.refuse("expected ',' or '}'")
		}
	}
}

// array reads the array whose opening bracket is at the offset.
func (p *parser) array() (Value, error) {
	if err := p.open(); err != nil {
		return Value{}, err
	}
	defer func() { p.depth-- }()
	if p.next() == ']' {
		p.i++
		return Value{kind: KindArray}, nil
	}
	var items []Value
	for {
		v, err := p.value()
		if err != nil {
			return Value{}, err
		}
		items = append(items, v)
		p.space()
		switch p.next() {
		case ',':
			p.i++
			p.space()
		case ']':
			p.i++
			return Value{kind: KindArray, items: items}, nil
		default:
			return Value{}, p.refuse("expected ',' or ']'")
		}
	}
}

// maxDigits is the most digits a protocol integer has: MaxSafe has 16.
const maxDigits = 16

// integer reads the protocol integer at the offset, deciding it from its text so that no number is
// rounded: at most 16 digits, refused at the seventeenth; no leading zero; no fraction or exponent; at
// most MaxSafe.
func (p *parser) integer() (Value, error) {
	start := p.i
	var n int64
	for p.i < len(p.b) && '0' <= p.b[p.i] && p.b[p.i] <= '9' {
		if p.i-start == maxDigits {
			return Value{}, p.refuse("a 17th digit")
		}
		n = n*10 + int64(p.b[p.i]-'0')
		p.i++
	}
	if p.i-start > 1 && p.b[start] == '0' {
		return Value{}, refuseAt(StepParse, "a leading zero", start)
	}
	if c := p.next(); c == '.' || c == 'e' || c == 'E' {
		return Value{}, p.refuse("a fraction or exponent")
	}
	if n > MaxSafe {
		return Value{}, refuseAt(StepParse, "an integer above 2^53 - 1", start)
	}
	return I(n), nil
}

// string reads the string whose opening quote is at the offset (RFC 8259 §7) and returns its text, its
// escapes decoded. The text is strict UTF-8 (RFC 3629) and holds no raw control character, no lone
// surrogate and no noncharacter, raw or escaped (RFC 7493 §2.1).
func (p *parser) string() (string, error) {
	start := p.i
	p.i++
	var out []byte
	for p.i < len(p.b) {
		switch c := p.b[p.i]; {
		case c == '"':
			p.i++
			return string(out), nil
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			out = utf8.AppendRune(out, r)
		case c < 0x20:
			return "", p.refuse("a raw control character")
		case c < utf8.RuneSelf:
			out = append(out, c)
			p.i++
		default:
			// utf8.DecodeRune refuses what RFC 3629 refuses: an overlong form, a surrogate, a code point
			// above U+10FFFF, a byte that starts no sequence and a sequence cut short.
			r, size := utf8.DecodeRune(p.b[p.i:])
			if r == utf8.RuneError && size == 1 {
				return "", p.refuse("invalid UTF-8")
			}
			if text.IsNoncharacter(r) {
				return "", p.refuse("a noncharacter")
			}
			out = append(out, p.b[p.i:p.i+size]...)
			p.i += size
		}
	}
	return "", &Error{Step: StepParse, msg: "a string not closed, from byte " + strconv.Itoa(start)}
}

// escape reads the escape whose backslash is at the offset and returns the character it stands for. An
// escaped high surrogate is the first half of a character only when an escaped low surrogate follows it
// at once (RFC 8259 §7); either half alone is refused.
func (p *parser) escape() (rune, error) {
	at := p.i
	p.i++
	c := p.next()
	p.i++
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		r, err := p.hex4(at)
		if err != nil {
			return 0, err
		}
		switch {
		case 0xDC00 <= r && r <= 0xDFFF:
			return 0, refuseAt(StepParse, "a lone surrogate", at)
		case 0xD800 <= r && r <= 0xDBFF:
			low := p.i
			if !bytes.HasPrefix(p.b[low:], []byte(`\u`)) {
				return 0, refuseAt(StepParse, "a lone surrogate", at)
			}
			p.i += 2
			r2, err := p.hex4(low)
			if err != nil {
				return 0, err
			}
			if r2 < 0xDC00 || r2 > 0xDFFF {
				return 0, refuseAt(StepParse, "a lone surrogate", at)
			}
			r = 0x10000 + (r-0xD800)<<10 + (r2 - 0xDC00)
		}
		if text.IsNoncharacter(r) {
			return 0, refuseAt(StepParse, "a noncharacter", at)
		}
		return r, nil
	}
	return 0, refuseAt(StepParse, "an escape RFC 8259 does not define", at)
}

// hex4 reads the four hex digits, in either case, that follow the \u of an escape whose backslash is at
// offset at.
func (p *parser) hex4(at int) (rune, error) {
	if len(p.b)-p.i < 4 {
		return 0, refuseAt(StepParse, `an escape \u without four hex digits`, at)
	}
	var r rune
	for _, c := range p.b[p.i : p.i+4] {
		var d byte
		switch {
		case '0' <= c && c <= '9':
			d = c - '0'
		case 'a' <= c && c <= 'f':
			d = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, refuseAt(StepParse, `an escape \u without four hex digits`, at)
		}
		r = r<<4 | rune(d)
	}
	p.i += 4
	return r, nil
}
