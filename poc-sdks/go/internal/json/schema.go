// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"slices"
	"strconv"
)

// The schema helpers below are step 4 of reading, which each object's reader builds from them. Their
// refusals are at StepSchema. A refusal names a member by the name the caller gave, never by a name or
// value from the input: a member the schema does not have is named by its position in the object.

// Exactly checks o's member names against an object's schema. It refuses o unless, checked in this order:
//
//  1. o is an object;
//  2. every name in required is a member's name: of those that are not, the first in LessUTF16 order is
//     the one the refusal names. A member whose value is null is present: a schema that refuses null
//     checks the member's type, as String, Integer and Bool do;
//  3. every member's name is in required or optional, and no name is repeated (a reader never gives an
//     object a repeated name; a constructed Value may hold one).
//
// Exactly checks names only, never values: each member's type and range are the caller's to check.
func Exactly(o Value, required, optional []string) error {
	if o.kind != KindObject {
		return refuse(StepSchema, "the value is not an object")
	}
	var missing string
	found := false
	for _, name := range required {
		if _, ok := Field(o, name); !ok && (!found || LessUTF16(name, missing)) {
			missing, found = name, true
		}
	}
	if found {
		return refuse(StepSchema, "the member "+strconv.Quote(missing)+" is missing")
	}
	// seen holds only schema names, so it stays as small as the schema.
	var seen []string
	for i, m := range o.members {
		if !slices.Contains(required, m.Name) && !slices.Contains(optional, m.Name) {
			return refuse(StepSchema, "member "+strconv.Itoa(i)+" is not one the object has")
		}
		if slices.Contains(seen, m.Name) {
			return refuse(StepSchema, "the member "+strconv.Quote(m.Name)+" is repeated")
		}
		seen = append(seen, m.Name)
	}
	return nil
}

// Field returns the value of o's member called name, and whether o is an object with that member.
func Field(o Value, name string) (Value, bool) {
	for _, m := range o.members {
		if m.Name == name {
			return m.Value, true
		}
	}
	return Value{}, false
}

// String returns the text of o's member called name, refusing o unless it has the member and it is a
// string.
func String(o Value, name string) (string, error) {
	v, err := member(o, name, KindString, "a string")
	return v.str, err
}

// Integer returns the value of o's member called name, refusing o unless it has the member and it is a
// protocol integer, in [0, MaxSafe]. A section that gives a narrower range checks it.
func Integer(o Value, name string) (int64, error) {
	v, err := member(o, name, KindInt, "an integer")
	if err == nil && (v.num < 0 || v.num > MaxSafe) {
		return 0, refuse(StepSchema, "the member "+strconv.Quote(name)+" is not a protocol integer")
	}
	return v.num, err
}

// Bool returns the value of o's member called name, refusing o unless it has the member and it is a
// boolean.
func Bool(o Value, name string) (bool, error) {
	v, err := member(o, name, KindBool, "a boolean")
	return v.boolean, err
}

// member returns o's member called name, refusing o unless it has the member and it is of kind k; what
// is k as the refusal names it.
func member(o Value, name string, k Kind, what string) (Value, error) {
	v, ok := Field(o, name)
	if !ok {
		return Value{}, refuse(StepSchema, "the member "+strconv.Quote(name)+" is missing")
	}
	if v.kind != k {
		return Value{}, refuse(StepSchema, "the member "+strconv.Quote(name)+" is not "+what)
	}
	return v, nil
}

// StringMap returns object v, a member that is a map by definition (such as a keyring's services), as a
// Go map, refusing v unless it is an object whose every member is a string. Its names are data, which the
// caller checks by its section's rules, so a refusal names a member by its position, never its name.
func StringMap(v Value) (map[string]string, error) {
	if v.kind != KindObject {
		return nil, refuse(StepSchema, "the value is not an object")
	}
	m := make(map[string]string, len(v.members))
	for i, member := range v.members {
		if member.Value.kind != KindString {
			return nil, refuse(StepSchema, "member "+strconv.Itoa(i)+" is not a string")
		}
		if _, ok := m[member.Name]; ok {
			return nil, refuse(StepSchema, "member "+strconv.Itoa(i)+" repeats a name")
		}
		m[member.Name] = member.Value.str
	}
	return m, nil
}
