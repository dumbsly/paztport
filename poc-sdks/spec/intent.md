# Intent

Intent is a set of facts the origin states about a request, which a receiver compares with the request it is sent.
It is the extension named `intent`. The origin's application states the facts, such as the amount a customer was
shown, and the origin puts them in its own [block](wire.md#blocks), to which its stamp's `ext` commits. Every later
hop forwards that block unchanged, so a receiver several hops on is handed the facts as the origin signed them, and
can refuse a request that asks for something else. This file says which limit intent narrows, what its item is, what
the origin and a receiver each do, the codes it gives, and what it does not do. The bytes of stamps and blocks are in
[wire.md](wire.md), and the checks in [verification.md](verification.md).

Intent is specified for HTTP only. It has no MCP form and no offline reading: an offline verifier gives none of its
codes.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [What it is for](#what-it-is-for) · [Facts and the item](#facts-and-the-item) ·
[The origin's part](#the-origins-part) · [The receiver's part](#the-receivers-part) ·
[How a receiver knows a fact is required](#how-a-receiver-knows-a-fact-is-required) ·
[A request that did not verify](#a-request-that-did-not-verify) · [Reason codes](#reason-codes) ·
[What every hop learns](#what-every-hop-learns) · [What it does not do](#what-it-does-not-do) ·
[Prior art](#prior-art) · [Conformance](#conformance)

## What it is for

A stamp binds the request its signer sends, so a compromised hop can make the calls its route allows with any
arguments ("A hop chooses what it sends", in the [known limits](../../docs/limits.md#limits-of-the-concept)). The
origin's stamp binds what the origin sent, but a later receiver does not see that request, so it cannot check its own
against it. Intent narrows that limit for the values the origin states as facts: a receiver that requires a fact
refuses a request whose own value differs from it. A compromised hop can still choose any value that is not a fact,
and can still make or withhold the calls its route allows ([What it does not do](#what-it-does-not-do)).

For example, a customer buys order `123` for 100. The entry point, which is the origin, states the facts `amount`,
`customer` and `order`. The order service then calls the payment service, which requires all three. The payment
service compares the charge it is asked for with the facts, and refuses a different amount `INTENT_DENIED`, though
the call comes on a valid route from a hop whose stamp verifies.

The facts are the origin's statement. A compromised origin can state any facts, as it can already start any allowed
route: only an entry point holds an origin key ([wire.md](wire.md#chains)).

## Facts and the item

A **fact** is a name and a value. Its name follows the rule for an extension name ([wire.md](wire.md#blocks)): 1 to
32 characters, each one of `a` to `z`, `0` to `9` and `-`. Its value is any JSON value [the reader](wire.md#reading)
takes, so a number is a protocol integer ([wire.md](wire.md#the-grammar)).

An intent item is a JSON object with exactly one member, `facts`: an object of fact names to values, with at least one
member.

```json
{ "facts": { "amount": 100, "customer": "c-42", "order": "123" } }
```

The reader refuses an object that names a member twice ([wire.md](wire.md#the-grammar)), so no fact appears twice.
Items travel inside blocks, so the core reads their bytes with the blocks, and this section gives their schema.

Only the first stamp's block, the origin's, may hold an intent item, and it holds at most one. A later block may name
`intent` with `[]`, which says its signer acts on the extension and has nothing to add ([wire.md](wire.md#blocks)).

The item carries no `rid`, salt or signature of its own. The origin's stamp carries the `rid`, and its `ext` commits
to the block, so the facts are tied to the request tree by the origin's signature. A later hop that alters the
origin's block fails [check 9a](verification.md#the-live-order) at every honest hop after it.

## The origin's part

The origin's application hands the SDK the facts for the request, and the SDK puts the item in the origin's block
under `intent`. The facts are values the application acts on, such as those it puts in its own outgoing call; the SDK
reads no body to find them. The origin needs no table and no route map. With no facts it puts no item. An origin that
puts an item acts on `intent`, since a name in `items` is that statement ([wire.md](wire.md#blocks)).

A hop between the origin and the receiver need not act on `intent`. It forwards the origin's block unchanged, as every
hop does ([wire.md](wire.md#blocks)).

Only an origin sends an item. An egress starts a new chain at the boundary, whose first stamp is the boundary stamp
([sessions.md](sessions.md#between-organisations)), so an egress MUST NOT put an `intent` item in the boundary block.
The origin's facts do not cross the boundary.

A verifier that sets `allowedExtensions` refuses a block that names `intent` unless the set holds it
([check 9b](verification.md#the-live-order)), and the origin's block reaches every hop after it. So a deployment adds
`intent` to every such set first, and only then has origins send facts and receivers require them.

## The receiver's part

A service that acts on `intent`, one whose `actsOn` holds it ([verification.md](verification.md#inputs)), runs these
checks on each request before the handler runs. They read what the service is handed under `intent`, verified or not:
for each stamp, in chain order, that its block does not name `intent`, or the items its block holds under it
([the live order](verification.md#the-live-order)). Each check runs only when the one before it held.

| # | Check | Refusal |
|---|---|---|
| P1 | The items handed over read, whether or not the hand-over is verified: the first stamp's block holds at most one item under `intent`, and that item reads as [an intent item](#facts-and-the-item); every later stamp's block holds none. | `400 INTENT_MISMATCH` |
| P2 | Every fact the handler requires ([below](#how-a-receiver-knows-a-fact-is-required)) is named in the item's `facts`, in a verified hand-over, checked once the service knows the handler the request will run ([the receiver's operation](verification.md#http-requests-and-responses)). With no item, or with no verified hand-over, no fact is named ([A request that did not verify](#a-request-that-did-not-verify)). | `403 INTENT_MISSING` |

An item that does not read is one that is not an object, one with another member, one with no `facts`, one whose
`facts` is not an object or is empty, or one with a fact name the name rule refuses. Two items in the origin's block,
or any item in a later block, fail P1 too. P1 runs at every operation of a service that acts on `intent`, one that
requires no fact included, and in either mode, so an item that does not read is refused the same way whether or not
the chain verified, as `influence` refuses its own ([influence.md](influence.md#entries)). Where the chain did not
read, nothing is handed on ("What a request served without verifying is handed", in
[the live order](verification.md#the-live-order)), so P1 has nothing to read. A request whose blocks fail check 9a is
never served over HTTP ([HTTP requests](verification.md#http-requests-and-responses)), so P1 never runs on it. A
service that acts on both extensions runs `influence`'s item check first, then P1.

Then the handler compares the request it was sent with the facts, and refuses a difference with
`403 INTENT_DENIED`. Which value of the request a fact is compared with is the handler's to say: the extension knows
only the facts' names and values, and reads nothing of the request.

> **A receiver acts on the value it compared.** A handler that compares a fact with its request MUST then use the
> compared value, and build whatever it sends on from compared values. It MUST NOT compare a parsed value and then
> relay the bytes it parsed.

Two readers of one body can disagree: a repeated member, a number's spelling, a field one honours and the other
ignores (compare "A binding binds the value read, not its text", in the
[known limits](../../docs/limits.md#limits-of-the-concept)). A handler that compared an amount it parsed and then
relayed the same bytes would let the next receiver read another amount from them, and the hop that wrote the body is
the one the comparison is there to check. This is the application's duty, and no SDK can check it.

## How a receiver knows a fact is required

A receiver MUST take the facts a handler requires from its own configuration, never from the request or its caller.
It holds, beside each handler that compares, the names of the facts that handler requires, so the requirement and the
comparison change together. Nothing is signed by the
policy owner and nothing is pinned: a change is a deployment of that service, and the root and keyrings stay as they
are.

A fact that is only sometimes present needs no rule. The origin's signature covers the whole item, so a name that is
not in `facts` is one the origin did not state, and a handler can rely on that absence in a verified hand-over.

## A request that did not verify

A fact is believed only from a hand-over that is verified: one the verifier made because the live order gave `OK` at
this hop. A request served without that has no facts: P1 still reads the items it is handed
([The receiver's part](#the-receivers-part)), but P2 and the handler believe none of them. That is a request served
in audit mode after a failure, or at a service that verifies no requests under a mode, where its live order did not
give `OK` or it runs none ([the live order](verification.md#the-live-order)), and a call in an unsafe session, where
nothing is handed on.

At a handler that requires a fact, such a request is refused `403 INTENT_MISSING`, in either mode. Serving it would let
the handler act on values that no verified origin stated, which is what the requirement is there to refuse. At a
handler that requires none, it is served as its mode says. In enforce mode verification refuses a request that fails
the live order first, with that check's code, and a request whose blocks fail check 9a is never served
([HTTP requests](verification.md#http-requests-and-responses)).

## Reason codes

| Code | HTTP | Given when |
|---|---|---|
| `INTENT_MISMATCH` | `400` | P1 fails: the items handed over under `intent`, verified or not, do not read. |
| `INTENT_MISSING` | `403` | P2 fails, or a request with no verified hand-over reaches a handler that requires a fact. |
| `INTENT_DENIED` | `403` | The handler compared its request with the facts and refused. |

Each refusal's body is `{"reason":"<code>"}` and nothing else
([what a refusal carries](verification.md#modes-and-refusals)). Each is given in either mode: it is the service's own
refusal, not a result of verification, so it does not follow audit mode. The statuses follow `influence`: `400` for an
item that does not read, `403` for a decision.

Like `influence`'s codes, these name no one and are never attributable
([attribution](verification.md#receivers-the-peer-and-attribution)). An item that does not read may have been passed
along by hops that could not read it, and a difference from a fact may have an honest cause, such as a service one
version behind. The service logs the last signer, and for an item that does not read the signer of its block, for its
operator.

## What every hop learns

Every fact, at every hop after the origin on every branch of the request tree, since the origin's block travels
unchanged to all of them, and anything that records those blocks keeps every fact too. So a fact must be a value every
service on the way may know: a card number is not. Identifiers already travel this way: an `influence` entry may carry
its owner in the blocks ([influence.md](influence.md#entries)).

## What it does not do

- **Privacy between hops.** Every hop reads every fact, and every record of the blocks keeps it. A value that must stay
  out of evidence cannot be a fact. The item is closed, so any further member is a format change for every
  implementation that acts on `intent`.
- **A requirement the policy owner signs.** It lives in each receiver's configuration, so nobody outside the service
  can see from the policy what it requires. A receiver deployed without its requirement serves every request, and
  nothing on the caller's side guards against that: `requires` is the direct caller's setting
  ([wire.md](wire.md#blocks)), and the direct caller is the hop the receiver checks.
- **Derived values.** A value worked out after the origin has no signer but the hop that sends it, so it cannot be a
  fact. A ceiling can: `amount-max` is a fact like any other, and a handler refuses an amount above it.
- **Anything across the boundary.** The origin's block does not cross, and an egress puts no intent item in the
  boundary block ([The origin's part](#the-origins-part)). A partner is handed no facts, so a partner handler that
  requires one refuses every call `INTENT_MISSING`. This rests on the egress keeping that MUST NOT: an item in a
  boundary block would be the egress's own statement, and a partner's P1 would read it as the first stamp's.
- **A budget.** A fact is a constraint, not a budget: it says what a request may ask for, not how often. Calls that
  each match the facts each pass the comparison. How often a hop may call a receiver in one request tree is the
  core's to limit, by the nonce key ([freshness and replay](verification.md#freshness-and-replay)).
- **Withholding.** A hop that never makes the call to the receiver that would compare is refused by no one, and
  nothing here reports it.

## Prior art

- **PSD2 dynamic linking.** The EU's rules on strong customer authentication for a remote payment (Commission
  Delegated Regulation (EU) 2018/389, Article 5) tie the authentication code to the amount and the payee, so a change
  to either makes the code invalid. Intent applies the same idea inside a mesh: what the customer was shown is signed
  at the entry, and a change on the way is refused where the payment is made.
- **OAuth Transaction Tokens**
  ([draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens),
  a working-group draft, not an RFC). A short-lived signed token, issued by a token service, that carries a request's
  context through one trust domain's call chain. Intent has the same shape, but its signature is one Paztport already
  has: the origin stamp's `ext` over the origin's block, tied to the request's `rid` and verified at every receiver. So
  it adds no token service and no second key. Nor does the draft say how a receiver knows a value is required; here
  the receiver's configuration says.
- **SD-JWT** ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)). An issuer signs one salted digest per claim, and
  claims that are always shown sit in the clear in the same signed object. Intent's facts are such clear claims. The
  format, JWT and base64url disclosures, does not fit a protocol whose one byte form is JCS.

## Conformance

The vectors file `vectors/intent.json`, written by the Java SDK and replayed by Java and Go, pins the extension: the
reading of an item, checks P1 and P2, a request that did not verify at a handler that requires a fact and at one that
does not, a service that does not act on `intent`, a verifier whose `allowedExtensions` lacks it, and each refusal's
exact status and body. A block altered after its stamp is the core's case, which `http-v4.json` pins already.
