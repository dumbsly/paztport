// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"slices"
	"strconv"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

// Wire returns v's canonical bytes, its JCS text (RFC 8785): no whitespace, an object's members sorted by
// their names' UTF-16 code units (LessUTF16), strings escaped as RFC 8785 §3.2.2.2 says, and integers as
// their digits. Array items keep their order.
//
// A writer writes nothing a reader refuses, and refuses the whole value rather than write a replacement:
// a string or member name that is not valid UTF-8 (the bytes of a lone surrogate among them) or holds a
// noncharacter, an integer that is not a protocol integer, a repeated member name, nesting deeper than
// MaxDepth, or bytes over WireBytes.
func Wire(v Value) ([]byte, error) {
	w := writer{}
	if err := w.value(v, 0); err != nil {
		return nil, err
	}
	if len(w.out) > WireBytes {
		return nil, refuse(StepWrite, "the wire bytes would be over the "+strconv.Itoa(WireBytes)+"-byte limit")
	}
	return w.out, nil
}

// Token returns v's token, the base64url of its wire bytes. It refuses what Wire refuses.
func Token(v Value) (string, error) {
	b, err := Wire(v)
	if err != nil {
		return "", err
	}
	return b64.Encode(b), nil
}

// File returns v in the file form: members in canonical order and strings escaped as Wire writes them,
// one member or item per line, indented two spaces a level, ": " between a name and its value, an empty
// object written {} and an empty array [], and a newline at the end. It refuses what Wire refuses, with
// FileBytes as its limit.
func File(v Value) ([]byte, error) {
	w := writer{indent: true}
	if err := w.value(v, 0); err != nil {
		return nil, err
	}
	w.out = append(w.out, '\n')
	if len(w.out) > FileBytes {
		return nil, refuse(StepWrite, "the file would be over the "+strconv.Itoa(FileBytes)+"-byte limit")
	}
	return w.out, nil
}

// writer appends a value's text to out.
type writer struct {
	out    []byte
	indent bool // the file form
}

// value writes v, which sits inside depth containers.
func (w *writer) value(v Value, depth int) error {
	switch v.kind {
	case KindNull:
		w.out = append(w.out, "null"...)
	case KindBool:
		w.out = strconv.AppendBool(w.out, v.boolean)
	case KindInt:
		if v.num < 0 || v.num > MaxSafe {
			return refuse(StepWrite, "an integer that is not a protocol integer")
		}
		w.out = strconv.AppendInt(w.out, v.num, 10)
	case KindString:
		return w.string(v.str)
	case KindArray:
		if depth == MaxDepth {
			return refuse(StepWrite, "nesting deeper than "+strconv.Itoa(MaxDepth))
		}
		w.out = append(w.out, '[')
		for i, item := range v.items {
			w.separate(i, depth+1)
			if err := w.value(item, depth+1); err != nil {
				return err
			}
		}
		w.close(len(v.items), depth, ']')
	case KindObject:
		if depth == MaxDepth {
			return refuse(StepWrite, "nesting deeper than "+strconv.Itoa(MaxDepth))
		}
		members, err := canonicalOrder(v.members)
		if err != nil {
			return err
		}
		w.out = append(w.out, '{')
		for i, m := range members {
			w.separate(i, depth+1)
			if err := w.string(m.Name); err != nil {
				return err
			}
			w.out = append(w.out, ':')
			if w.indent {
				w.out = append(w.out, ' ')
			}
			if err := w.value(m.Value, depth+1); err != nil {
				return err
			}
		}
		w.close(len(members), depth, '}')
	}
	return nil
}

// separate starts item or member i of a container whose contents sit at depth: after a comma unless it is
// the first, and in the file form on a line of its own.
func (w *writer) separate(i, depth int) {
	if i > 0 {
		w.out = append(w.out, ',')
	}
	w.newline(depth)
}

// close ends a container of n items or members that sits at depth with bracket: on a line of its own in
// the file form, unless the container is empty.
func (w *writer) close(n, depth int, bracket byte) {
	if n > 0 {
		w.newline(depth)
	}
	w.out = append(w.out, bracket)
}

// newline starts a line indented for depth, in the file form.
func (w *writer) newline(depth int) {
	if !w.indent {
		return
	}
	w.out = append(w.out, '\n')
	for range depth {
		w.out = append(w.out, "  "...)
	}
}

// string writes s quoted and escaped as RFC 8785 §3.2.2.2 says: a two-character escape for each of the
// seven characters that have one, \u00xx in lowercase hex for every other character below U+0020, and
// every other character as its own UTF-8 bytes.
func (w *writer) string(s string) error {
	if err := checkText(s); err != nil {
		return err
	}
	const hex = "0123456789abcdef"
	w.out = append(w.out, '"')
	for i := range len(s) {
		// Each byte of a multi-byte sequence is 0x80 or above, so testing bytes finds every character
		// that is escaped.
		switch c := s[i]; c {
		case '"', '\\':
			w.out = append(w.out, '\\', c)
		case '\b':
			w.out = append(w.out, '\\', 'b')
		case '\f':
			w.out = append(w.out, '\\', 'f')
		case '\n':
			w.out = append(w.out, '\\', 'n')
		case '\r':
			w.out = append(w.out, '\\', 'r')
		case '\t':
			w.out = append(w.out, '\\', 't')
		default:
			if c < 0x20 {
				w.out = append(w.out, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xF])
			} else {
				w.out = append(w.out, c)
			}
		}
	}
	w.out = append(w.out, '"')
	return nil
}

// canonicalOrder returns a copy of members sorted by LessUTF16, refusing a name a reader would refuse.
func canonicalOrder(members []Member) ([]Member, error) {
	for _, m := range members {
		if err := checkText(m.Name); err != nil {
			return nil, err
		}
	}
	sorted := slices.Clone(members)
	slices.SortFunc(sorted, func(a, b Member) int { return compareUTF16(a.Name, b.Name) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Name == sorted[i-1].Name {
			return nil, refuse(StepWrite, "a repeated member name")
		}
	}
	return sorted, nil
}

// checkText refuses s unless it is text a reader reads: valid UTF-8, and no noncharacter.
func checkText(s string) error {
	if !text.Valid(s) {
		return refuse(StepWrite, "a string that is not valid UTF-8, such as the bytes of a lone surrogate")
	}
	if text.HasNoncharacter(s) {
		return refuse(StepWrite, "a string holding a noncharacter")
	}
	return nil
}
