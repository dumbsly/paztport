// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package stamp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// EmptyBlock is the block that attaches nothing, the zero Block; its stamp's ext is "".
var EmptyBlock = Block{}

// emptyBlockText is the JCS text of the empty block, which the zero Block has no field to hold.
const emptyBlockText = `{"items":{},"requires":[]}`

// Block is what one stamp's signer attaches (wire.md, Blocks). The core never reads an item, so each is held
// as the JCS text of one JSON value: the module has no public JSON tree, and a string cannot change once the
// block holds it. The fields are unexported and every accessor hands out a copy, so a block cannot change
// after it is built and its commitment cannot drift from the stamp that signed it. The zero Block is the empty
// block, and its maps have no inherited members, so a name such as "constructor" finds nothing where it is
// not listed.
type Block struct {
	items    map[string][]string // extension name to its items' JCS text, in the order its signer wrote them
	requires []string            // sorted, none twice
	text     string              // the block's JCS text; "" only for the zero Block
}

// IsExtensionName reports whether name is an extension name: 1 to 32 of a-z, 0-9 and '-'. Names are ASCII, so
// byte order is UTF-16 code unit order, and this file sorts and compares them as plain strings.
func IsExtensionName(name string) bool {
	if len(name) < 1 || len(name) > 32 {
		return false
	}
	for i := range len(name) {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// NewBlock returns the block naming each extension in items with its items, each the JCS text of one JSON
// value, in the order given, and requiring requires, which it sorts by UTF-16 code units. It refuses a name
// that is not an extension name, a name twice in requires, and an item that is not exactly the canonical
// text of one value the strict reader takes. It copies what it is given.
func NewBlock(items map[string][]string, requires []string) (Block, error) {
	own := make(map[string][]string, len(items))
	for _, name := range slices.Sorted(maps.Keys(items)) {
		list := items[name]
		if !IsExtensionName(name) {
			return Block{}, fmt.Errorf("paztport stamp: a block can't name %q: not an extension name", name)
		}
		texts := make([]string, len(list))
		for i, item := range list {
			// The wire reader refuses whitespace, members out of order and numbers that are not
			// protocol integers, so text it reads is its own canonical text.
			if _, err := json.ReadWire([]byte(item)); err != nil {
				return Block{}, fmt.Errorf("paztport stamp: item %d of %q is not the canonical text of one value: %w",
					i, name, err)
			}
			texts[i] = item
		}
		own[name] = texts
	}
	req := slices.Clone(requires)
	slices.Sort(req)
	for i, name := range req {
		if !IsExtensionName(name) {
			return Block{}, fmt.Errorf("paztport stamp: a block can't require %q: not an extension name", name)
		}
		if i > 0 && name == req[i-1] {
			return Block{}, fmt.Errorf("paztport stamp: a block can't require %q twice", name)
		}
	}
	return build(own, req)
}

// build writes the block's text, which also checks the depth limit where the block will travel: one level
// deeper than alone, as an element of the array of blocks.
func build(items map[string][]string, requires []string) (Block, error) {
	if len(items) == 0 && len(requires) == 0 {
		return Block{}, nil
	}
	b := Block{items: items, requires: requires}
	v, err := b.value()
	if err != nil {
		return Block{}, err
	}
	if _, err := json.Wire(json.Arr(v)); err != nil {
		return Block{}, fmt.Errorf("paztport stamp: the block can't be written: %w", err)
	}
	text, err := json.Wire(v)
	if err != nil {
		return Block{}, fmt.Errorf("paztport stamp: the block can't be written: %w", err)
	}
	b.text = string(text)
	return b, nil
}

// value is the block as a JSON value, its items read back from their text.
func (b Block) value() (json.Value, error) {
	members := make([]json.Member, 0, len(b.items))
	for name, list := range b.items {
		vs := make([]json.Value, len(list))
		for i, item := range list {
			v, err := json.ReadWire([]byte(item))
			if err != nil {
				return json.Value{}, fmt.Errorf("paztport stamp: an item of %q: %w", name, err)
			}
			vs[i] = v
		}
		members = append(members, json.Member{Name: name, Value: json.Arr(vs...)})
	}
	names := make([]json.Value, len(b.requires))
	for i, name := range b.requires {
		names[i] = json.S(name)
	}
	return json.Obj(
		json.Member{Name: "items", Value: json.Obj(members...)},
		json.Member{Name: "requires", Value: json.Arr(names...)},
	), nil
}

// Names returns the names the block's items name, in UTF-16 code unit order. A name only in requires is not
// named. It is a copy.
func (b Block) Names() []string {
	names := slices.Collect(maps.Keys(b.items))
	slices.Sort(names)
	return names
}

// Items returns a copy of the items under name, each its JCS text, and whether the block names it: an empty
// list and true when it names the extension with nothing to add, nil and false when it does not name it.
func (b Block) Items(name string) ([]string, bool) {
	list, ok := b.items[name]
	if !ok {
		return nil, false
	}
	return append([]string{}, list...), true
}

// Requires returns the extensions the block's signer requires of the next hop, sorted, as a copy.
func (b Block) Requires() []string {
	return slices.Clone(b.requires)
}

// Commit returns the stamp's ext: "" for the empty block, else b64url(SHA-256(JCS(block))).
func (b Block) Commit() string {
	if b.text == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(b.text))
	return b64.Encode(sum[:])
}

// Wire returns the block's JCS text, {"items":{},"requires":[]} for the empty block.
func (b Block) Wire() []byte {
	if b.text == "" {
		return []byte(emptyBlockText)
	}
	return []byte(b.text)
}

// Blocks is the blocks one per stamp, in chain order, as they travel. On the wire it is a JSON array of the
// blocks, carried as a token beside the chain.
type Blocks []Block

// ReadBlocks reads the blocks from their token, the base64url of the JCS bytes of an array of blocks, as
// ParseBlocks reads the bytes. A token that is not canonical base64url or is over the token limit is an error.
func ReadBlocks(tok string) (Blocks, error) {
	v, err := json.ReadToken(tok)
	if err != nil {
		return nil, fmt.Errorf("paztport stamp: the blocks token does not read: %w", err)
	}
	return blocksFromValue(v)
}

// ParseBlocks reads blocks from the JCS bytes of an array of blocks, by wire.md's block schema: exactly the
// members items and requires, every name an extension name, every value in items an array, and requires
// strictly increasing by UTF-16 code units. Anything else, null included, is an error.
func ParseBlocks(wire []byte) (Blocks, error) {
	v, err := json.ReadWire(wire)
	if err != nil {
		return nil, fmt.Errorf("paztport stamp: the blocks do not read: %w", err)
	}
	return blocksFromValue(v)
}

// ParseBlock reads one block from its JCS bytes, by the schema ParseBlocks reads each block of an array by
// (wire.md, Blocks). Anything else, null included, is an error.
func ParseBlock(wire []byte) (Block, error) {
	v, err := json.ReadWire(wire)
	if err != nil {
		return Block{}, fmt.Errorf("paztport stamp: the block does not read: %w", err)
	}
	b, err := blockFromValue(v)
	if err != nil {
		return Block{}, fmt.Errorf("paztport stamp: the block: %w", err)
	}
	return b, nil
}

func blocksFromValue(v json.Value) (Blocks, error) {
	if v.Kind() != json.KindArray {
		return nil, errors.New("paztport stamp: the blocks are not an array")
	}
	items := v.Items()
	bs := make(Blocks, len(items))
	for i, item := range items {
		b, err := blockFromValue(item)
		if err != nil {
			return nil, fmt.Errorf("paztport stamp: block %d: %w", i, err)
		}
		bs[i] = b
	}
	return bs, nil
}

func blockFromValue(o json.Value) (Block, error) {
	if err := json.Exactly(o, []string{"items", "requires"}, nil); err != nil {
		return Block{}, err
	}
	named, _ := json.Field(o, "items")
	if named.Kind() != json.KindObject {
		return Block{}, errors.New(`the member "items" is not an object`)
	}
	items := make(map[string][]string, len(named.Members()))
	for _, m := range named.Members() {
		if !IsExtensionName(m.Name) {
			return Block{}, fmt.Errorf("%q is not an extension name", m.Name)
		}
		if m.Value.Kind() != json.KindArray {
			return Block{}, fmt.Errorf("the items of %q are not an array", m.Name)
		}
		texts := []string{}
		for _, item := range m.Value.Items() {
			text, err := json.Wire(item)
			if err != nil {
				return Block{}, err
			}
			texts = append(texts, string(text))
		}
		items[m.Name] = texts
	}
	list, _ := json.Field(o, "requires")
	if list.Kind() != json.KindArray {
		return Block{}, errors.New(`the member "requires" is not an array`)
	}
	requires := []string{}
	for _, n := range list.Items() {
		if n.Kind() != json.KindString || !IsExtensionName(n.Str()) {
			return Block{}, errors.New("a name in requires is not an extension name")
		}
		// strictly increasing refuses both an unsorted pair and a name twice
		if last := len(requires) - 1; last >= 0 && n.Str() <= requires[last] {
			return Block{}, errors.New("requires is unsorted or holds a name twice")
		}
		requires = append(requires, n.Str())
	}
	return build(items, requires)
}

// Wire returns the blocks' wire bytes, the JCS text of the array. It refuses what the writer refuses, past the
// wire limit included, as Chain.Wire does.
func (bs Blocks) Wire() ([]byte, error) {
	vs := make([]json.Value, len(bs))
	for i, b := range bs {
		v, err := b.value()
		if err != nil {
			return nil, fmt.Errorf("paztport stamp: the blocks can't be written: block %d: %w", i, err)
		}
		vs[i] = v
	}
	return wire(json.Arr(vs...))
}

// Token returns the blocks' token, the base64url of their wire bytes. It refuses what Wire refuses.
func (bs Blocks) Token() (string, error) {
	b, err := bs.Wire()
	if err != nil {
		return "", err
	}
	return b64.Encode(b), nil
}
