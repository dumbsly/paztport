// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package influence is the extension named influence (influence.md): a record of what content shaped a request
// or an agent's output, and the rules that read it. It is a set of functions over what the verifier hands on. The
// core carries an extension's items in each stamp's block without reading them; this package writes influence's
// items into a block and reads the ones handed on under [Name].
//
// An [Entry] says one piece of content was in the context: its [Class], where it came from and what it was. A
// hop that acts on influence signs, with each request it sends, a block from [RequestBlock] holding the entries it
// added itself, and names influence in every block it signs, with [] when it has nothing to add. A service reads
// what it is handed, one block per stamp, with [ReadRequest]; an item that is not an entry is INFLUENCE_MISMATCH,
// online through [Decide] and offline through [Items]. A server labels each result it attests with a [Label], in
// the response's block from [ResponseBlock]; a caller adds the entries [ResponseEntries] gives for the response.
//
// The rules read whether every stamp names influence, since a stamp whose block does not is a hop that may have
// read anything, and then only each entry's class and owner. [GuardedWriteRefused] decides a write to a public
// destination: the every-stamp rule, then [PublicWriteRefused], the owner-aware rule, by which untrusted content
// may steer a write of a customer's own data to that customer, never someone else's data, or data whose owner
// nobody knows. [ShapedOnlyByTrusted] decides whether a service may write a record that later decisions take as
// fact.
//
// An egress sending a request to another organisation sends blinded influence in place of its entries:
// [Reduce] groups them by class and owner and sends one entry per group, whose h is a salted commitment to
// the group's originals. The partner's verdict under the rules is the one it would reach on the
// originals, and it learns neither their sources nor their hashes. The sender can later show what a sent
// entry stood for with an [Opening], which [Opens] checks. The egress's boundary key, which salts every
// commitment, is read from its file with [LoadBoundaryKey].
//
// An item, and a list of entries or of labels, and an opening, travel as their canonical (JCS) bytes and are read
// by the spec's rules for wire bytes. A reader refuses anything else with an error naming the member and the
// position that broke the rule, never quoting the input.
package influence
