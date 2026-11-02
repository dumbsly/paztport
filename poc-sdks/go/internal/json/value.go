// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"slices"
	"strconv"
)

// MaxSafe is the largest protocol integer, 2^53 - 1. A protocol integer is one in [0, MaxSafe], written
// as its decimal digits.
const MaxSafe = 1<<53 - 1

// Kind is the kind of JSON value a [Value] holds. The protocol has no other numbers than protocol
// integers, so its only number kind is KindInt.
type Kind int

// The kinds of value. The zero Value is null.
const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindString
	KindArray
	KindObject
)

// String returns the kind's name.
func (k Kind) String() string {
	switch k {
	case KindNull:
		return "null"
	case KindBool:
		return "bool"
	case KindInt:
		return "int"
	case KindString:
		return "string"
	case KindArray:
		return "array"
	case KindObject:
		return "object"
	}
	return "Kind(" + strconv.Itoa(int(k)) + ")"
}

// Value is a JSON value. It does not change once built: a reader builds it, or the constructors [Obj],
// [Arr], [S], [I], [B] and [Null] do, and the accessors return copies. An object keeps its members in the
// order they were read or given; a writer puts them in canonical order.
type Value struct {
	kind    Kind
	str     string
	num     int64
	boolean bool
	members []Member
	items   []Value
}

// Member is one member of an object: a name and its value.
type Member struct {
	Name  string
	Value Value
}

// Obj returns an object holding members, in the order given.
func Obj(members ...Member) Value {
	return Value{kind: KindObject, members: slices.Clone(members)}
}

// Arr returns an array holding items.
func Arr(items ...Value) Value {
	return Value{kind: KindArray, items: slices.Clone(items)}
}

// S returns the string s.
func S(s string) Value {
	return Value{kind: KindString, str: s}
}

// I returns the integer n. A writer refuses it unless it is a protocol integer, in [0, MaxSafe].
func I(n int64) Value {
	return Value{kind: KindInt, num: n}
}

// B returns the boolean b.
func B(b bool) Value {
	return Value{kind: KindBool, boolean: b}
}

// Null returns null, the zero Value.
func Null() Value {
	return Value{}
}

// Kind returns the kind of value v holds.
func (v Value) Kind() Kind {
	return v.kind
}

// Members returns a copy of object v's members, in the order they were read or given, or nil if v is not
// an object.
func (v Value) Members() []Member {
	return slices.Clone(v.members)
}

// Items returns a copy of array v's items, or nil if v is not an array.
func (v Value) Items() []Value {
	return slices.Clone(v.items)
}

// Str returns string v's text, or "" if v is not a string.
func (v Value) Str() string {
	return v.str
}

// Int returns integer v's value, or 0 if v is not an integer.
func (v Value) Int() int64 {
	return v.num
}

// Bool returns boolean v's value, or false if v is not a boolean.
func (v Value) Bool() bool {
	return v.boolean
}

// Step is a reading step, or writing, at which bytes or a value are refused.
type Step string

// The steps. StepSize, StepParse and StepCanonical are the spec's reading steps 1 to 3, StepSchema its
// step 4, the object's own; StepWrite is a writer's refusal.
const (
	StepSize      Step = "size"
	StepParse     Step = "parse"
	StepCanonical Step = "canonical"
	StepSchema    Step = "schema"
	StepWrite     Step = "write"
)

// Error is a refusal: the step that refused, and a message naming the rule and, where there is one, the
// byte offset. It never quotes the input.
type Error struct {
	Step Step
	msg  string
}

// Error returns the refusal as "<step>: <rule>". It names no package: the package is internal, and each
// exported reader or writer that refuses wraps the error in its own package's words.
func (e *Error) Error() string {
	return string(e.Step) + ": " + e.msg
}

// refuse returns the refusal of rule at step.
func refuse(step Step, rule string) *Error {
	return &Error{Step: step, msg: rule}
}

// refuseAt returns the refusal of rule at step, at byte offset at.
func refuseAt(step Step, rule string, at int) *Error {
	return &Error{Step: step, msg: rule + " at byte " + strconv.Itoa(at)}
}
