// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package influence records what content shaped a request or an agent's output, and the rules that read
// that record.
//
// An [Entry] says one piece of content was in the context: its [Class], where it came from and what it
// was. A call carries the list as its influence, and its last stamp commits to it with [Commit], so a hop
// can't drop an entry without breaking the stamp. A server labels each result it attests with a [Label],
// which the caller adds to its influence as an entry once the whole response verifies.
//
// Two rules read only each entry's class and owner. [PublicWriteRefused] decides a write to a public
// destination: untrusted content may steer a write of a customer's own data to that customer, never
// someone else's data, or data whose owner nobody knows. [ShapedOnlyByTrusted] decides whether a service
// may write a record that later decisions take as fact.
//
// An egress sending a request to another organisation sends blinded influence in place of its entries:
// [Reduce] groups them by class and owner and sends one entry per group, whose h is a salted commitment to
// the group's originals. The partner's verdict under the rules is the one it would reach on the
// originals, and it learns neither their sources nor their hashes. The sender can later show what a sent
// entry stood for with an [Opening], which [Opens] checks. The egress's boundary key, which salts every
// commitment, is read from its file with [LoadBoundaryKey].
//
// Lists of entries and of labels, and openings, travel as their canonical (JCS) bytes and are read by the
// spec's rules for wire bytes. A reader refuses anything else with an error naming the member and the
// position that broke the rule, never quoting the input.
package influence
