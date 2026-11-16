# Sessions

How two sides open a session and decide how far to trust each other, what a session's status lets through, and how a
chain crosses from one organisation to another. A session is a **profile**: a way of using the core that adds no
check to it and does not use the [block](wire.md#blocks) slot. The bytes of stamps, roots and keyrings are in
[wire.md](wire.md), the checks in [verification.md](verification.md), and the extension influence, which a session's
calls may carry and a boundary blinds, in [influence.md](influence.md).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [The handshake](#the-handshake) · [Over HTTP](#over-http) · [The session id](#the-session-id) ·
[Status](#status) · [Unsafe sessions](#unsafe-sessions) · [The server decision](#the-server-decision) ·
[Recorded handshakes](#recorded-handshakes) · [Between organisations](#between-organisations)

## The handshake

Before it stamps any call, a client opens a session with the JSON-RPC method `paztport/session`. Each side
sends its signed root, its policy key, its keyring and a fresh nonce, and the server signs the reply. There is
one session per connection: a new handshake replaces the current one, with its keyring, nonce cache and
[served classes](influence.md#over-mcp), so calls signed for the old session are refused.

The params are `{"request": "<token>"}`, the [request](#the-request)'s token, and the result is
`{"reply": "<token>"}`, the [reply](#the-reply)'s token, each the base64url of the object's JCS bytes
([wire.md](wire.md#carrying-an-object)). MCP lets every request and result carry `_meta`, such as a progress token:
the server ignores the params' `_meta`, and the client the result's. A server MUST answer params with any other
member, or whose `request` is missing, not a string or does not read, with JSON-RPC error `-32602` (Invalid params),
and open no session. A client MUST take a result with any other member, or whose `reply` is missing or not a string,
as `MALFORMED_REPLY`, as it takes a reply that does not read ([its check](#the-clients-check-of-the-reply)).
`v4.json` pins the server's reading in `sessionParams`, and the client's in `sessionResult` (MCP profile).

### The request

| Field | Type | Meaning |
|---|---|---|
| `clientRoot` | signed root, or `null` | The client's [signed root](wire.md#the-signed-root), whole: its `notAfter` travels inside it. `null` asks for an unsafe session. |
| `clientPolicyKey` | string | The client's policy public key. |
| `clientKeyring` | object | The client's services: name to public key. |
| `clientKeyringSig` | non-empty string | The client policy key's signature over the keyring: the `sig` of its [signed keyring](wire.md#the-signed-keyring), over `"paztport-keyring\n" ‖ JCS({ notAfter: clientKeyringNotAfter, policy: clientPolicyKey, services: clientKeyring })`. |
| `clientKeyringNotAfter` | integer | The keyring's `notAfter`. |
| `nonce` | string | 16 fresh random bytes, base64url. |

`clientKeyringSig` is checked over the request's own `clientKeyringNotAfter` member, and a root's signature over
its own `notAfter` member, as for any [signed root or keyring](wire.md#keys-and-files). A window moved in transit
therefore fails its signature.

A request is read from its bytes as [wire bytes](wire.md#reading), and has exactly the members above; a client root
has exactly a [signed root's](wire.md#the-signed-root) members. Over MCP it is read from the token in the params'
`request`. A server MUST answer a request that does not read, or that is not an object, has a member the table
does not list, or whose `clientRoot` is neither `null` nor an object of exactly string `rootId`, `root` and `sig`
and an integer `notAfter`, whose `clientKeyring` is not an object of strings or names a service that is not a [route
node](wire.md#routes), whose `clientPolicyKey` or `nonce` is not a string, whose `clientKeyringSig` is missing,
`null`, not a string or empty, or whose `clientKeyringNotAfter` or `clientRoot.notAfter` is missing or not an
integer in [0, 2^53 − 1] (`null` included), with JSON-RPC error `-32602` (Invalid params), and open no session. It
MUST also open none when the nonce is not 16 bytes or the client root's `sig` is not 64, and MUST answer that with a
JSON-RPC error other than `-32601`, so the client takes its replacement path
([below](#the-clients-check-of-the-reply)). A request that opens no session leaves the connection's current session,
if any, in place: the TypeScript server fails before it replaces it.

A `clientKeyringSig` that is a string but does not verify is no malformed request: the session is unsafe live, and
offline it is not attested.

`v4.json` pins the reading of a request in `sessionRequest`: a well-formed request, and one whose `clientKeyringSig`
is missing, `null`, empty or a number, one with no `clientKeyringNotAfter`, one whose client root has no
`notAfter` and one whose signed keyring names a service that is not a route node, each malformed.

### The reply

| Field | Type | Meaning |
|---|---|---|
| `serverRoot` | signed root, or `null` | The server's signed root, whole, its `notAfter` inside it. |
| `serverPolicyKey` | string | The server's policy public key. |
| `serverKeyring` | object | The server's services: name to public key. |
| `serverKeyringSig` | string, entry-key form only | The server policy key's signature over the keyring: the `sig` of its [signed keyring](wire.md#the-signed-keyring), over `"paztport-keyring\n" ‖ JCS({ notAfter: serverKeyringNotAfter, policy: serverPolicyKey, services: serverKeyring })`. |
| `serverKeyringNotAfter` | integer, entry-key form only | The `notAfter` that `serverKeyringSig` was made over, present exactly when `serverKeyringSig` is. |
| `serverReplyCert` | object, entry-key form only | A [reply certificate](wire.md#the-reply-certificate) from the server policy key for the server's entry service and its key. |
| `nonce` | string | 16 fresh random bytes from the server, base64url. |
| `sess` | string | [The session id](#the-session-id). |
| `status` | `"attested"` or `"unsafe"` | See [Status](#status). |
| `disabled` | array of strings | The tools refused in this session: the server's unsafe-session list when `status` is `"unsafe"`, and `[]` when it is `"attested"`. |
| `extensions` | array of strings | The extensions the server acts on: [extension names](wire.md#blocks), sorted by their UTF-16 code units, with no name twice, and `[]` for none. Present whatever the `status`. |
| `sig` | string | The signature over the reply's other fields: by the entry service's key in the entry-key form, by the server policy key in the policy-key form. |

A reply is read from its bytes as [wire bytes](wire.md#reading), and has exactly the members above, the three of
the entry-key form each only when present; a non-null `serverRoot` has exactly a
[signed root's](wire.md#the-signed-root) members, and a `serverReplyCert` exactly a
[reply certificate's](wire.md#the-reply-certificate). Over MCP it is read from the token in the result's `reply`.
A reply without `extensions`, or whose `extensions` is not an array of extension names, sorted, with no name twice,
does not read (`MALFORMED_REPLY`).

A reply is in one of two forms, told apart only by which fields are present:

- **The entry-key form** carries both `serverKeyringSig` and `serverReplyCert`, and `sig` is made with the key the
  certificate names, the server's entry service's own key. The policy key signs the keyring and the certificate
  offline, so it need not be online to answer handshakes.
- **The policy-key form** carries neither, and `sig` is made with the server policy key.

A reply with one of the two fields and not the other is in neither form, and fails the check. A server SHOULD send
the entry-key form, so that its policy private key can stay offline. Either way the server MUST say
`"attested"` only after the checks of [Status](#status): only the signing key differs between the forms.

The reply's signed bytes are:

```
utf8( "paztport-session-reply\n" ‖ JCS(reply without its "sig" field) )
```

That is the reply as read, every member but `sig`: `serverKeyringSig`, `serverKeyringNotAfter` and
`serverReplyCert` included when present. A reply reads only from its canonical bytes, so these are the JCS bytes of
the object received, less its `sig`.

That one signature covers the server's root, keyring, nonce, session id, status, disabled list and extensions.
In the policy-key form the keyring is therefore signed by the policy key through the reply. In the entry-key form
the signer is only the entry service, so the keyring carries the policy key's own signature, and the certificate says
that the signing key is the entry service's and is still current. Without the keyring's signature the keyring
would be only the reply's own claim, and could name any key as the entry service's.

### The client's check of the reply

A client pins the server's policy key in advance, and knows the name of the server's entry service,
`serverEntry`, from its own configuration. It MUST NOT take `serverEntry` from the reply. The check is made at a
time `now`, in milliseconds since the Unix epoch: live, the client's current time. In order, the first failure is
the outcome:

1. The reply reads, with exactly the members above; `serverKeyringSig`, when present, is a string beside a
   `serverKeyringNotAfter`; `serverKeyringNotAfter`, when present, and the `notAfter` of a non-null `serverRoot` are
   integers in [0, 2^53 − 1]; every name in `serverKeyring` is a [route node](wire.md#routes);
   `serverReplyCert`, when present, is a [reply certificate](wire.md#the-reply-certificate) with exactly its
   members; and `extensions` is an array of extension names, sorted, with no name twice. A field whose value is
   `null` is present (`MALFORMED_REPLY`).
2. `serverPolicyKey` equals the pinned key (`PIN_MISMATCH`).
3. The signature, then the roots and the session id (`BAD_SIGNATURE`):
   - When `serverKeyringSig` or `serverReplyCert` is present: both are; the keyring
     `{ policy: serverPolicyKey, services: serverKeyring, sig: serverKeyringSig, notAfter: serverKeyringNotAfter }`
     verifies under the pinned key; the certificate verifies under the pinned key; its `svc` equals `serverEntry`;
     `serverKeyring` has a member of its own named `serverEntry`, equal to the certificate's `key`;
     `now <= notAfter`; `now <= serverKeyringNotAfter`; and `sig` verifies under the certificate's `key`.
   - When neither is present: the reply has no `serverKeyringNotAfter` either, and `sig` verifies under the
     pinned key. In this form the keyring has no signature of its own (the policy key signs it through the reply),
     so a keyring window there is vouched for by nothing, and fails like either field without the other.

   Then, in both forms: an `"attested"` reply has both roots non-null; `sess` equals the session id the client
   derives from its own request and the reply; and `serverRoot`, when present, verifies under the pinned key and
   `now <= serverRoot.notAfter`.
4. `status` is `"attested"`: the session is attested. Otherwise it is unsafe (`UNSAFE`).
5. When the session is attested and the client's configuration requires extensions of this server, each of them
   is in `extensions` (`EXTENSION_REQUIRED`).

**A client that requires extensions.** A client whose configuration requires extensions of a server makes calls
to it only in an attested session whose reply lists each of them. On `EXTENSION_REQUIRED` it makes no call in that
session. Nor does it make a call in an unsafe session with that server, however the session came to be unsafe:
the reply's `status` said so (step 4), or the client took the replacement path, below, after an outcome from 1 to
3, a JSON-RPC error or a timeout. A server that answers the handshake with `-32601` (Method not found) has no
Paztport, and is treated as an unsafe session for this rule: no calls unless the switch below is set. A client that
sends no handshake at all, having no pin to check a reply against, is in an unsafe session with that server for this
rule too. The requirement is the caller's guard for a server that does not act on the extension, so neither the
server, by answering `"unsafe"`, nor anyone able to make the handshake fail can switch it off. A configuration
switch lets the client continue instead, in each of these cases. After `EXTENSION_REQUIRED` it makes calls in the
attested session the reply gave it, and each call's block carries `requires` only for the required names the reply
lists ([wire.md](wire.md#blocks)). In an unsafe session, however it came to be unsafe, one with no handshake included,
it makes calls unattested, as a client with no requirement does. Over MCP, a client that makes no call in a session
with a server does not list the server's tools either (it sends no `tools/list`): a tool it cannot call has no use,
and its description would reach the model unrecorded.

`EXTENSION_REQUIRED` is an outcome of this check, as `PIN_MISMATCH` and `MALFORMED_REPLY` are; it shares its name
with the verifier's code, as `BAD_SIGNATURE` already does. A mesh has no handshake, so there `requires` does this
work on each call ([check 9c](verification.md#the-live-order)).

The server's root, and in the entry-key form its keyring, are judged at `now` whatever the reply's `status`: an
expired one is `BAD_SIGNATURE`, so the client takes its replacement path. A window is relied on only after the
policy key's signature over it has verified, the root's under the pin and the keyring's as above: the entry key
signs the reply, windows included, so the reply's own signature never vouches for one. A server whose own material
has expired ([Status](#status)) is therefore unsafe at the client too. This is the live check; a recorded
handshake is checked offline ([Recorded handshakes](#recorded-handshakes)).

The form is decided by which fields are present, never by which key verifies. A client MUST NOT try the pinned
key when the certificate's key fails, or the other way round: a reply stripped of its certificate, or given one,
would then pass under whichever key signed it. A lookup of `serverEntry` in `serverKeyring` MUST find only the
object's own members, so that a name such as `constructor` finds nothing in a keyring that does not list it.

**What the entry key can do.** A compromised entry-service key, while a certificate for it is unexpired, can forge
a reply's nonce, session id, status, disabled list and extensions, and can present any root or keyring the policy
key signed that has not yet expired, but can make none, and can't revive an expired one: roots and keyrings,
windows included, are verified under the pinned key, and a client refuses an expired one live. That key already
signs every response stamp the server attests, so a server that attests its responses already relies on it. Once
its certificates have expired it signs nothing a client accepts, so the revocation delay is the certificate's
lifetime ([wire.md](wire.md#the-reply-certificate)).

**Domain separation.** Each kind of signed message starts with its own prefix, so that no signature can be read
as another kind: session replies `"paztport-session-reply\n"`, reply certificates `"paztport-reply-cert\n"`,
roots `"paztport-root\n"`, keyrings `"paztport-keyring\n"`, responder events `"paztport-event\n"`, and stamps
`"paztport-stamp\n"`.

After an outcome from 1 to 3, or a JSON-RPC error or timeout, the server may have opened an attested session
the client can't use, so every unstamped call would be refused. The client SHOULD replace it: it sends the same
request again with `clientRoot: null` and a fresh nonce, and trusts the reply to that either way. A reply
`-32601` (Method not found) means the server has no Paztport, so there is nothing to replace. The replacement is an
unsafe session, so a client that requires extensions of the server makes no call in it unless its switch lets it
continue, as above. `EXTENSION_REQUIRED` does not lead to the replacement: the reply was sound, and the replacement
would only give the client an unsafe session with a server known not to act on the extension, in which it makes
no call.

`v4.json` pins the check in `sessionReply`, each case a reply checked at `now` against `pin` and `serverEntry`, with the
extensions the client `requires`: the entry-key form attested and unsafe, the policy-key form attested, a check at the
certificate's `notAfter` and one 1 ms after it, and forms that fail: a certificate for another service, for a key other
than the keyring's entry key, or signed by another policy key; a reply signed by another service; a keyring altered
after signing or signed by another policy key; an entry absent from the keyring; either of `serverKeyringSig` and
`serverReplyCert` without the other, whichever key signed the reply; neither field, signed by the keyring's entry key; a
server root signed by the entry key; an empty `serverKeyringSig`; a `null` `serverKeyringSig` and a `null`
`serverReplyCert`, a certificate `notAfter` that is not an integer, a member the reply does not have and a keyring that
names a service that is not a route node, each malformed; a pin mismatch; a `serverKeyringNotAfter` moved after signing,
which fails the signature, and one dropped, one that is not an integer and one that is `null`, which are malformed; a
server root `notAfter` moved after signing, which fails the signature, and one dropped and one that is not an integer,
which are malformed; and an `extensions` that is missing, `null`, not an array, unsorted, names one twice or names
`Example`, each malformed, and one changed after signing, which fails the signature. It pins the judging of the server's
material too: a server root at its `notAfter`, and expired (in the entry-key form, in the policy-key form and in an
unsafe reply), and expired with its `notAfter` moved past `now` in a reply signed again by the entry key; a server
keyring at its `notAfter` and expired; and a `serverKeyringNotAfter` in a policy-key reply. And it pins step 5: an
attested reply that lists what the client requires, lists more, lists none of it, or lists one of two names it requires;
and, to a client with a requirement, an unsafe reply, another key's reply, a reply whose server root has expired and a
reply without `extensions`, each given the outcome of an earlier step, not `EXTENSION_REQUIRED`. `sessionRequirement`
pins what a client that requires extensions may do afterwards: after each outcome of the check, after a JSON-RPC
error or a timeout, and after a Method not found answer, with and without its switch, whether it makes calls and the
`requires` its calls carry; and that a client with no requirement makes calls after a failed handshake and after an
unsafe reply.

### Over HTTP

The Java and Go SDKs carry the handshake over HTTP, in version 4
([conformance](README.md#conformance)). The request and the reply are the same JSON objects, and the session is
the same.

| Part | Rule |
|---|---|
| Endpoint | `POST /paztport/session`. The body is the request's JCS bytes, with `Content-Type: application/json`, and a `200` returns the signed reply's JCS bytes. |
| A body that does not read as a request: bytes that are not its JCS bytes (another member order, or a newline after them, as a file an editor saved ends), and a request [above](#the-request) refuses (a `clientKeyringSig` that is missing, `null`, not a string or empty, a `clientKeyring` naming a service that is not a route node, and a `clientKeyringNotAfter` or `clientRoot.notAfter` that is missing or not an integer in [0, 2^53 − 1], included) | `400 {"error":"INVALID_PARAMS"}`. The server reads at most the [wire limit](wire.md#limits), 256 KiB, and answers more than that the same way. |
| A request that opens no session | `400 {"error":"NO_SESSION"}`: the checks of [The request](#the-request), or no client certificate, or one that names no single service or no issuer. |
| `404` | The server has no Paztport. The Java and Go clients cannot tell this from any other failed handshake, so they send the replacement anyway; that is answered `404` too, and the call fails. |

**Sessions are kept by id, each bound to the peer that opened it.** HTTP has no connection to hold a session, so
the server records, with each session, the peer the TLS layer authenticated: the client certificate's issuer (its
RFC 4514 string) and its subject's common name, the service, never a name in the body. Over MCP nothing
changes: one session per connection, as [above](#the-handshake).

- **A handshake adds a session and replaces none.** So clients that share a certificate, such as replicas, each
  keep their own, up to the limit below, and a client that opens a new session does not cut off calls still in
  flight in its earlier one. A request that opens no session changes no session.
- **A peer holds at most N sessions**, a limit the server sets (16 in the Java SDK). A handshake that would give
  it more evicts its least recently used. Replicas that share a certificate are one peer, so beyond N of them
  evict each other's least recently used sessions. A call that then names an evicted session is refused, and the
  client opens a new one on its next call. A server MUST NOT evict one peer's session for another peer's
  handshake.
- **A session no call has used for the server's idle period expires** (15 minutes in the Java SDK).

So the server keeps at most N sessions for each peer its CAs vouch for.

**Calls name their session** in the `X-Path-Session` request header, whose value is the session id
([wire.md](wire.md#http)).

- **No header** (or a blank one, [wire.md](wire.md#http)) means the caller never opened a session. The server
  treats the call as in an unsafe session.
- **A header that names no live session opened by this call's peer** is refused
  `403 {"reason":"SESSION_UNKNOWN"}`. A server MUST take a session as the call's only when the issuer and the name
  it recorded for it are both those of the call's authenticated peer. A call with no client certificate, or one whose
  certificate has no issuer or names no single service, matches no session. So this covers another peer's id,
  the same name's id under another issuer (issuers are told apart by their distinguished name, not by the CA's
  key), an evicted or expired id, and one from before the server restarted.
  The server MUST NOT take it as unsafe, or a caller refused in an attested session could step down to an unsafe
  one by naming a wrong id. A client that gets it drops the session and opens a new one on its next call. A client
  reads a refusal from its [wire bytes](wire.md#reading), `{"reason":"<code>"}` and no other member; any other body
  gives no reason, and the session is kept.
- **Otherwise** the call is in that session, attested or unsafe as the handshake said, and the session's idle
  period starts again.

In an attested session each call is verified by a verifier of its own, built from the client's keyring and
root as the handshake presented them, with `sess` = the session id, so a stamp made in one session never
verifies in another ([verification.md](verification.md#http-requests-and-responses)). Inside one organisation's
mesh there is no handshake, and `sess` stays `""`.

In an unsafe session the server verifies nothing and believes nothing from the call: it hands its extensions no
items and holds no verified chain, whatever headers came. The reply's `disabled` lists endpoints as
`<METHOD> <path pattern>`, such as `POST /refund`, where the pattern is that of the handler the server
dispatches the request to, not the path the caller wrote. So `/refund;x=1` and `//refund` are refused as
`POST /refund`. A `HEAD` is refused wherever the matching `GET` is. These are not
[operations](wire.md#operations): an unsafe session verifies nothing, so no operation is named or confirmed.
A refusal is `403 {"reason":"UNSAFE_SESSION"}` and the handler does not run.

## The session id

The session id binds both roots, both nonces and the client's policy key and keyring:

```
sess = b64url( H( 0x02 ‖ flags ‖ clientRootSig ‖ serverRootSig ‖ clientNonce ‖ serverNonce ‖ keysHash ) )
```

| Part | Bytes | Value |
|---|---|---|
| `0x02` | 1 | A fixed domain byte. |
| `flags` | 1 | `0x01` when the client root is present, plus `0x02` when the server root is present. |
| `clientRootSig` | 64, or 0 | The client root's `sig`, decoded. Omitted when `clientRoot` is `null`. |
| `serverRootSig` | 64, or 0 | The server root's `sig`, decoded. Omitted when `serverRoot` is `null`. |
| `clientNonce` | 16 | The request's `nonce`, decoded. |
| `serverNonce` | 16 | The reply's `nonce`, decoded. |
| `keysHash` | 32 | `H(utf8(JCS({ "clientPolicyKey": clientPolicyKey, "clientKeyring": clientKeyring })))` |

Each decoded value MUST have exactly the length shown, or there is no session id. `flags` says which roots are
present, so input without a root can't be read as input with one. `v4.json` pins the layout in `deriveSessionId`.
It does not cover `clientKeyringSig` or `clientKeyringNotAfter`: it binds the keyring itself, and the server
checks the signature, over that window, before it attests.

Every stamp in the session carries `sess`, so a chain made for one session fails in any other.

## Status

A server opens an **attested** session only when all of these hold, and an **unsafe** one otherwise:

- `clientRoot` and its own root are both present;
- `clientRoot` verifies under `clientPolicyKey`, and its own root under its own policy key;
- `clientPolicyKey` is one of the client policy keys the server has pinned;
- `clientKeyringSig` verifies as the signature of the keyring
  `{ policy: clientPolicyKey, services: clientKeyring, notAfter: clientKeyringNotAfter }` under `clientPolicyKey`;
- both keyrings and both roots are current at the handshake, at the server's time `now`:
  `now <= clientRoot.notAfter` and `now <= clientKeyringNotAfter`, and the same for the server's own root and
  keyring.

A server with no pinned client keys MUST open every session unsafe. Without the pin, anyone could make a policy
key, sign a root and keyring with it, and be attested. Without the keyring signature, the keyring would be the
client's own claim. Pinning the policy key rather than a root lets the client rotate its roots and keyrings
without being pinned again.

Without the windows, a root or keyring the client's policy owner once signed would be attested for ever, a narrowed
policy or a retired key among them. Each client window is relied on only once the signature over it has verified,
so one moved in transit makes the session unsafe: the root's own signature is all that guards the root's window. A
server whose own root or keyring has expired while it runs degrades rather than stops: it opens every new session
unsafe, refusing the tools in its unsafe list and running the rest as for any unattested caller. Sessions it
attested earlier are still verified against the client's material, and their calls are refused `POLICY_EXPIRED`
once that expires ([verification.md](verification.md#the-live-order)).

`v4.json` pins this in `sessionStatus`, each case a request, the server's own root and keyring, its policy key, the
client keys it pinned and `now`: attested; an unpinned client key; the client's root and keyring each at its
`notAfter`, expired, and expired with its window moved past `now`; the server's root and keyring at their
`notAfter`; and each expired.

## Unsafe sessions

An unsafe session is graded trust, not a refusal. In it:

- The server does not verify calls, and does not attest results.
- Every tool in `disabled` is refused with `UNSAFE_SESSION`; every other tool runs, ungated. A server's default
  list SHOULD hold every write tool: a tool left off it runs with no influence rule at all.
- A client that acts on influence counts every result as `local-untrusted`
  ([influence.md](influence.md#content-labels)).

A call made before any handshake is treated as in an unsafe session.

## The server decision

The server decides each call in this order, verifying it only in an attested session
([verification.md](verification.md#the-mcp-server-and-client)):

1. A call that failed verification is refused with its code.
2. In an attested session, a call holding an item that an extension the server acts on refuses is refused with that
   extension's code, `INFLUENCE_MISMATCH` for an influence item that does not read
   ([influence.md](influence.md#entries)).
3. In an attested session, a write the server guards is decided by the extensions it acts on
   ([influence.md](influence.md#over-mcp) says how influence decides one). Anything else is allowed.
4. In an unsafe session, or with no session, the tools in `disabled` are refused (`UNSAFE_SESSION`).

A refusal is a result with `isError: true` and `_meta["paztport/verdict"]` the token of `{ "reason": <code> }`, and
the tool does not run. An audit-mode server runs the call anyway, and its verdict adds `"audit": true`. A server
attests a result only for a call that verified.

## Recorded handshakes

A record keeps the request's token as sent and the reply's as received, and a verifier reads each as
[wire bytes](wire.md#reading), as [above](#the-handshake).

Offline, a recorded handshake opened an attested session only when the reply's `status` is `"attested"`, the
reply passes steps 1 to 4 of the client's check against the recorded pin and the server's entry service from the
verifier's own configuration, both roots verify against their sides' policy keys, and the keyring signature
verifies. Step 5 reads the client's live configuration, which a record does not hold. A recorded request that is
not a well-formed request, a missing `clientKeyringSig` or a member a request does not have included, opened no
attested session.

The handshake record carries no signed time, so it is judged at each call's recorded time, the call's last stamp's
`ts`, which the client signed: `now` in the check is the time of the record being judged. One session can therefore
be attested for the calls recorded up to its limits and not for those after them. Its limits are the certificate's
`notAfter` (entry-key form) and the `notAfter` of each root and keyring, the client's and the server's. A verifier
asking whether the session was attested at all judges it at the earliest of those, since each is an upper bound. A
recorded response is limited only by the server's root window and, in the entry-key form, the server
keyring's, once the signatures covering them verify: the client's windows and the certificate do not limit it.

There is no client pin offline. The server's signed `"attested"` reply, whose session id binds the client's
policy key and keyring, is its statement that it pinned them.

A root or keyring is judged at the record's time, on both sides, as above, but only after its own signature has
verified: the root's under its side's policy key, the client keyring's under the client policy key, and the server
keyring's under the pin. Each signature is checked over its own window, so one moved in the record fails its
signature offline too, and an inherited one never counts. One dropped from the record leaves a root or keyring
without a window, which a reader refuses, so the handshake opened no attested session.

## Between organisations

When a request crosses from one organisation to another, the receiving organisation (the partner) MUST NOT see
the sender's internal chain, which is the map the protocol keeps private. A boundary attestation crosses
instead. The Java SDK implements this section over HTTP, in `BoundaryClient` for the sender and in partner mode
for the partner, and the Go SDK in `boundary.Egress` for the sender and `paztporthttp.Sessions` for the partner,
both in version 4 ([conformance](README.md#conformance)); the TypeScript SDK does not. Implementations
that bridge two organisations MUST follow it.

**The sender's egress service.** The sender's last internal hop before the boundary is its egress service. It
MUST:

1. Verify the internal chain it received, as a receiver, in [the live order](verification.md#the-live-order),
   and refuse the request if it fails. A request that did not pass the live order at this hop, or that has no
   request scope to be in, MUST NOT cause anything to be signed or sent, the handshake included. So a service
   with no verifier, one on which Paztport is off ([outside the modes](verification.md#modes-and-refusals)), a
   chain that failed in audit mode, and an origin cannot be the egress for that request.
2. Start a new chain at the boundary with exactly one stamp, the **boundary stamp**, signed with the egress
   service's own key, a key in the sender's signed keyring:
   - `svc`: the egress service;
   - `rid`: the internal chain's `rid`, unchanged;
   - `ts`: the time it signs;
   - `sess`: the id of the session the sender opened with the partner;
   - `rcv`: the partner's entry service;
   - `bind`: the binding of the request it sends;
   - `ext`: the commitment to the boundary stamp's [block](wire.md#blocks), the one it sends (step 3);
   - `prev`: `""`.

   A boundary stamp MUST have a non-empty `sess`, so it is never valid inside a mesh, where `sess` is `""`.
3. Send the boundary stamp's block and the proof for the route `<egress>/<partner entry>`, which the sender's root
   MUST hold. The boundary chain is one stamp, so it carries one block, the egress's own. What that block holds
   across a boundary is each extension's to say: influence crosses as
   [blinded entries](influence.md#blinded-influence), one per class and owner.
4. Never forward an internal stamp. So the partner learns one service name and what the boundary block holds, not
   the route or the sources behind it, and check 6 (every stamp carries the session) holds unchanged.
5. In an unsafe session, sign no stamp and send no block. The partner would not verify the stamp, and a block can
   hold what is private, as influence's owners are. The call carries only the session id.
6. Pin the partner's policy key and check the handshake reply against it, with `serverEntry` the partner's entry
   service, step 5 included ([above](#the-clients-check-of-the-reply)). Over HTTP, a reply the client cannot use, an
   HTTP error (a `404` included) or no answer within the handshake's timeout (10 s in the Java SDK) is followed by
   the replacement with no root, and the session is taken as unsafe whatever that reply says. From a server with no
   Paztport the replacement gets a `404` too, and the call fails. A reply that fails step 5 is not followed by the
   replacement. An egress whose configuration requires extensions of the partner makes calls to it only in an
   attested session whose reply lists each of them, as a client does ([above](#the-clients-check-of-the-reply)):
   it makes no call after a reply that fails step 5, nor in an unsafe session with the partner, whether the reply
   said `"unsafe"` or the session is the replacement, unless its configuration switch lets it continue.
7. Take every partner reply as unattested. The partner does not attest what it answers, so nothing it says
   counts as more: an egress that acts on influence records each reply as one `local-untrusted` entry
   ([influence.md](influence.md#content-labels)).

The Java SDK's `BoundaryClient` also checks, when it is built, that its own root and keyring verify under its own
policy key, since a partner could not attest either; that the partner's URL is a scheme and an authority with no
path; and, per call, that the path will be sent exactly as given and cannot change the host. A call refused for
that is refused before any I/O. A `403 SESSION_UNKNOWN` clears the session, so the next call opens a new one; the
refused call is not retried, since it may have changed something. A `403 POLICY_EXPIRED` clears it too: the
partner gives that to every call in an attested session once the client's root or keyring has passed its
`notAfter`, so the next call's handshake gives an unsafe session, and the client logs its own expiry once. Because
a refused call is not retried, a session the partner has expired would fail the next call, so the client also
drops a session no call has used for its own idle period (10 minutes in the Java SDK), and the next call opens a
new one. That period SHOULD be below the partner's.

**The partner.** The partner MUST pin the sender's policy key in advance, out of band, as partner onboarding.
It pins the key, not a root, so the sender can rotate roots and keyrings without being pinned again. In the
handshake the sender is the client: it sends its signed root, policy key, keyring and keyring signature, and the
partner attests the session only if the policy key is one it pinned. **An unpinned key gives an unsafe
session**, not a refusal: the partner serves what it allows to unattested callers and disables the rest.

The partner verifies the boundary chain in the live order against the sender's root and keyring from the
session, with the egress service as an allowed origin, `receiver` = its own entry service and
`receiverInRoute = true`, and the authenticated peer. What it does with the boundary block's items is their
extensions' to say: [influence.md](influence.md#blinded-influence) says how a partner that acts on influence
applies the owner-aware rule to the blinded entries.

The partner signs its handshake replies in either form ([above](#the-reply)). The Java SDK's partner sends the
entry-key form: it holds its entry service's key and a current reply certificate for it, and its policy key stays
offline. It checks at startup that its keyring verifies under its own pin and holds that key, and that the
certificate names it and has not expired. It does not attest what it answers. In the Java SDK, partner mode
(`paztport.partner.enabled`) replaces the inbound filter with one that has no modes and sends no responder
events; its properties are in the [Java SDK README](../java/README.md#partner-mode).

What the partner can still learn: the boundary proof is the same on every request over that route, so it can
count and cluster requests by route. It also sees what the boundary block holds: with influence, each request's
classes and owners, which the rule needs, and not the sources behind them, which cross only as blinded commitments
that the sender can open. The [known limits](../../docs/limits.md#limits-of-the-concept) cover these.
