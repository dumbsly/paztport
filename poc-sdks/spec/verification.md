# Verification

How a receiver checks a chain: the live order, freshness and replay, the receiver and peer checks, who a result
names, the MCP and HTTP checks around the live order, the two modes and what a refusal carries, the offline order
for recorded chains, and the reason codes; then how a responder checks the events it is sent. The bytes are in
[wire.md](wire.md).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [Inputs](#inputs) · [The live order](#the-live-order) · [Freshness and replay](#freshness-and-replay) ·
[Receivers, the peer and attribution](#receivers-the-peer-and-attribution) ·
[The MCP server and client](#the-mcp-server-and-client) ·
[HTTP requests and responses](#http-requests-and-responses) · [Modes and refusals](#modes-and-refusals) ·
[Offline verification](#offline-verification) · [Reason codes](#reason-codes) ·
[Receiving an event](#receiving-an-event) · [Guidance for a responder](#guidance-for-a-responder)

## Inputs

A verifier MUST fail closed: a malformed input is a typed rejection, never an exception out of the verifier and
never a pass. Every input below comes from the verifier's own configuration or its transport, never from the
request.

| Input | Meaning |
|---|---|
| `stamps` | The chain as received. |
| `expectedBind` | The binding the receiver computed for what it received ([wire.md](wire.md#bindings)). |
| `influence` | The influence entries received with the chain. |
| `proof` | The route proof received with the chain. |
| `receiver` | What the last stamp's `rcv` must name: the receiver's own name, or for a response, the calling client's `svc`. |
| `receiverInRoute` | Whether the route ends at `receiver`: true for a call, false for a response. |
| `peer` | Optional; null is the same as absent. The sender the transport authenticated, `{ svc, inst }`: its service name and its network address, for example from an mTLS certificate. |
| `keyring` | Service name to public key, from a keyring verified against its policy key ([wire.md](wire.md#the-signed-keyring)) and current. A key is looked up by own name only: inherited or default entries MUST NOT match. |
| `root`, `rootId` | The pinned signed root: verified against its policy key ([wire.md](wire.md#the-signed-root)) and current. |
| `policyNotAfter` | The earliest `notAfter` of that keyring and root, in ms since the Unix epoch: the last moment the policy owner vouches for both. |
| `allowedOrigins` | The services that may sign an origin stamp. |
| `sess` | The session id every stamp must carry. |
| `nonces`, `nonceKey` | The replay cache and this chain's key in it. |
| `now` | The verifier's clock, in ms since the Unix epoch. |

## The live order

A live verifier runs these checks in this order, and the first that fails is the result. The order is part of the
protocol: the vectors pin the code each case gives, so two implementations that order the checks differently
disagree.

| # | Check | Fails with |
|---|---|---|
| 0 | `now` is at most `policyNotAfter`. A missing `policyNotAfter`, or one that is not an integer in [0, 2<sup>53</sup> − 1], fails. A non-finite `now` is left to check 7. | `POLICY_EXPIRED` |
| 1 | The chain reads from its bytes ([wire.md](wire.md#chains)): the JCS bytes of a non-empty array of v3 stamps, each with exactly a stamp's members ([field rules](wire.md#stamp-field-rules)). A stamp whose `v` is not 3, or that has any other member, does not read. | `CHAIN_MISSING` |
| 2 | No signed field of any stamp holds `\|`, `rcv` included. | `BAD_SIGNATURE` |
| 3 | The origin's `svc` is in `allowedOrigins`. | `BAD_ORIGIN` |
| 4 | For each stamp in order: its `svc` has a key in `keyring` and its signature verifies under it (`BAD_SIGNATURE`), and its `prev` is `""` for the origin and the previous stamp's `sig` otherwise (`BROKEN_LINK`). Only after the whole chain passes that loop: each stamp's `rcv` is the next stamp's `svc`, and the last stamp's `rcv` is `receiver`. | `BAD_SIGNATURE`, `BROKEN_LINK`, then `BINDING_MISMATCH` |
| 5 | Every stamp carries the origin's `rid`. | `RID_MISMATCH` |
| 6 | Every stamp carries `sess`. | `SESSION_UNKNOWN` |
| 7 | Freshness: the last stamp's `ts` is within `CALL_MAX_AGE_MS` of `now`, either way; the origin's `ts` is at most `RUN_MAX_AGE_MS` before `now` and at most `CALL_MAX_AGE_MS` after it. A non-finite `now` or limit fails. | `EXPIRED` |
| 8 | The last stamp's `bind` equals `expectedBind`. | `BINDING_MISMATCH` |
| 9 | The influence parses, and the last stamp's `infl` equals its commitment. | `INFLUENCE_MISMATCH` |
| 10 | The nonce cache remembers keys for at least 2 × `CALL_MAX_AGE_MS`, and `nonceKey` is new to it. A new key is recorded. | `REPLAY` |
| 11 | The route, the stamps' `svc` values then `receiver` when `receiverInRoute`, is proven against the root ([proof checks](wire.md#proof-object)). | `PATH_NOT_ALLOWED` |
| 12 | With a `peer`, `peer.svc` equals the last stamp's `svc`. | `PEER_MISMATCH` |

Otherwise the result is `OK`.

Why this order:

- **The verifier's own policy first.** Check 0 is about the verifier's configuration, not the request, so it
  precedes even parsing the stamps: past `policyNotAfter` the keyring and root no longer say which keys and
  routes the policy owner allows, and no later check means anything against them. It names no one (see
  attribution below). It also spends no nonce key.
- **Receivers after the signature loop.** A bad signature or link anywhere always beats a bad `rcv`, so a
  forged chain is reported as forged, not as misdirected.
- **A receiver mismatch is `BINDING_MISMATCH`.** `rcv` is part of what the stamp binds: a chain signed for
  another receiver is bound to another request, exactly as a chain spliced onto another body is.
- **The cache is checked before it is spent.** A cache that forgets sooner than twice the call window could
  forget a key while a replay of it is still fresh, so it fails closed before recording anything.
- **The peer check runs last**, so every other check keeps its code when a transport adds a peer.

## Freshness and replay

| Constant | Value | Meaning |
|---|---|---|
| `CALL_MAX_AGE_MS` | `5000` (5 s) | How far the last stamp's time may be from `now`, either way, and how far the origin may be in the future. |
| `RUN_MAX_AGE_MS` | `1800000` (30 min) | How long a run's origin stays usable. An agent run reuses one origin for many calls, so the origin may be older than one call window. |
| `NONCE_TTL_MS` | `15000` (15 s) | How long a nonce cache remembers a key. It MUST be at least 2 × `CALL_MAX_AGE_MS`. |

Inside one HTTP mesh a request tree is a single call, not a run, so a mesh verifier MAY set `RUN_MAX_AGE_MS` to
`CALL_MAX_AGE_MS`: the origin's stamp is then held to the call window too. The Java mesh does: both are
`paztport.max-age-ms` (5000), unless `paztport.run-max-age-ms` sets the run's apart. Its stamps carry `sess = ""`,
since a mesh opens no session.

The nonce key names the request and the direction, so a call, its response and a local step with the same ids
can't spend each other's keys:

| Chain | `nonceKey` |
|---|---|
| MCP tool call, server side ([MCP profile](README.md#the-mcp-profile)) | `<rid>\|<callId>\|req` |
| MCP response, client side ([MCP profile](README.md#the-mcp-profile)) | `<rid>\|<callId>\|resp` |
| Local step ([MCP profile](README.md#the-mcp-profile)) | `<rid>\|<callId>\|local` |
| HTTP request (receiver side) | `<rid>\|<last svc>\|req` |
| HTTP response (caller side) | `<rid>\|<target>\|resp` |

`<rid>` is the origin's `rid` and `<callId>` the call's `paztport/callId` (for a local step, the tool call id).
`<last svc>` is the request chain's last signer, and `<target>` the service the caller sent the request to.
An HTTP call has no call id, so its keys name the pair of services instead: a service calls a given receiver at
most once per request tree, and a second call is `REPLAY`.

## Receivers, the peer and attribution

**The receiver checks.** In a v3 chain every stamp names the hop it was handed to (check 4). So a chain
forwarded unchanged to a service it was not signed for fails `BINDING_MISMATCH`, wherever it is sent, before
the route is looked at. A receiver MUST supply its own name as `receiver` from its configuration, never from the
request. For a call that name is also the end of the route. For a response, `receiver` is the caller's own
`svc` and `receiverInRoute` is false, so the route ends at the last signer. Over MCP that route is the server's
own hops, and the client is not on it. Over HTTP it is the request's own route, the caller included, because
the response stamp extends the chain the caller sent.

**Naming the receiver.** The caller MUST stamp the receiver's policy name as the last stamp's `rcv`: the name the
receiver supplies as `receiver`, under which the policy owner's keyring and routes know it. A stamp that names the
destination any other way, by an address, an alias or a port, fails check 4 at an honest receiver
(`BINDING_MISMATCH`). How a caller maps a destination to that name is its deployment's configuration, never
something the request or the destination says. Over HTTP the same name is the caller's `<target>`: in the response's
nonce key, as the service the response stamp must be by, and in the `src` (`http:<target>`) of what the response
adds to its influence. An egress names its partner's entry service by configuration
([sessions-and-influence.md](sessions-and-influence.md#between-organisations)). (The Java SDK takes the name from
the URL's host by default: [Java SDK README](../java/README.md#paztport-spring).)

**The peer check.** A transport that authenticates the sender (mTLS, for example) SHOULD pass it as `peer`. Check
12 then requires the last signer to be that sender. Only `svc` is compared: a certificate is issued per
service, not per instance, and `peer.inst` is the transport's address for the sender, not a signed value. With
no peer, check 12 is skipped.

**Attribution.** Every result carries `suspectSvc` and `suspectInst`, the party a responder may act against. It
goes to the verifier's own logs and to its [events](wire.md#events), never to the caller in a refusal
([Modes and refusals](#modes-and-refusals)):

- **`POLICY_EXPIRED` names no one**, peer or not: expiry is the verifier's own material running out, not
  anything the sender did.
- **With a peer**, every result of checks 1 to 12 names the peer, `OK` included:
  `suspectSvc = peer.svc` and `suspectInst = peer.inst`. The transport authenticated that sender, so it is the
  party that really sent this request, whatever the chain says. The MCP wrappers' own pre-checks, below, run
  before the live order and name no one.
- **Without a peer**, only `OK` and `PATH_NOT_ALLOWED` name a suspect: `suspectSvc` is the last stamp's `svc`
  and `suspectInst` its `inst`. By then the signatures, links, receivers, times, binding and replay checks have
  held, so that service's key really signed this request for this receiver. Every other result leaves both
  empty, because the name would be unsigned, or the genuine stamp would belong to another request (a replayed
  or altered capture).
- Without a peer, `suspectInst` is the signing service's own claim. Its key proves the service, not the
  instance.

## The MCP server and client

This section belongs to [the MCP profile](README.md#the-mcp-profile).

The MCP transport wraps the live order with checks of its own, before the chain is verified. The TypeScript
MCP wrappers (`verifyCall`, `verifyMcpResponse`, `McpServerSession.checkCall`) pass no peer, because stdio has
no TLS, so for MCP over stdio the live order ends at check 11, and the peer check is core's.

**A tool call, on the server.** The server checks a call only in an attested session
([sessions-and-influence.md](sessions-and-influence.md#status)), against the client's root and keyring from the
handshake, with `allowedOrigins` = the client's origin service, `receiver = mcp:<serverId>.<tool>`,
`receiverInRoute = true` and `nonceKey = <rid>|<callId>|req`. In order:

1. `params` is an object with a string `name` and an object `_meta`, the name holds no `/` or `|`, the server
   id no `/`, `|` or `.`, `paztport/callId` is a string, and `paztport/chain` is a token that reads as a chain
   ([wire.md](wire.md#mcp-v3)) (`CHAIN_MISSING`). The proof and influence are read from their tokens by the live
   order; a member that is not a string is read as a token that does not read.
2. The `tools/call` binding can be computed (`BINDING_MISMATCH`).
3. The live order, 0 to 12, with `policyNotAfter` the earlier of the client root's `notAfter` and
   `clientKeyringNotAfter`.
4. The server reports `PATH_NOT_ALLOWED` against the client's policy as `CLIENT_PATH_NOT_ALLOWED`, so its logs
   tell the client's policy from its own.

The influence is returned only when the call verifies. Then the server decides on the call
([sessions-and-influence.md](sessions-and-influence.md#the-server-decision)). A refusal is answered as a result
with `isError: true` and the token of its verdict in `paztport/verdict`, and is not signed.

**A response, on the client.** The client checks a response only in an attested session, against the server's
root and keyring from the signed handshake reply as read
([sessions-and-influence.md](sessions-and-influence.md#the-reply)), with `allowedOrigins` = the server's entry
service as the client's own configuration names it (`["mcp-entry"]` in the agents demo), never a value from the reply,
`receiver` = the client's own `svc`,
`receiverInRoute = false`, `influence = []` and `nonceKey = <rid>|<callId>|resp`. In order:

1. The call's `rid` and `callId` are strings, `callId` holds no `\n`, and `_meta["paztport/attestation"]` is a token
   whose attestation reads ([wire.md](wire.md#mcp-v3)): an object with exactly a `chain` of stamps, a `proof` that
   reads as a [proof object](wire.md#proof-object), a string `resultHash` and an array of well-formed `labels`
   (`CHAIN_MISSING`); a proof that does not read is not taken as no proof.
2. The first stamp's `rid` is the call's (`RID_MISMATCH`).
3. `resultHash` equals the result binding of the result received (`BINDING_MISMATCH`).
4. The live order, 0 to 12, with `expectedBind` = the response binding of `resultHash`, the call id and the
   labels, and `policyNotAfter` the server root's `notAfter`, or in the entry-key form the earlier of it and
   `serverKeyringNotAfter`. In the policy-key form the keyring carries no signature of its own, only the reply's.

The labels count as influence only when the whole response verifies. A response that fails, or arrives in an
unsafe session, counts as `local-untrusted`.

**A verdict, on the client.** A refusal is unsigned by design: it can only withhold a result, never add
influence. A client reads a result's `paztport/verdict` from its token ([wire.md](wire.md#mcp-v3)). It MUST treat a
result with a non-audit verdict as "the tool did not run" and record nothing from it, and MUST treat one whose
verdict does not read, a value that is not a token included, as a refusal with the reason `UNKNOWN`, never as a
result or an audit note. A verdict's `reason` is server data that can reach a model, so a client MUST keep it only
when it is one of these codes, and MUST replace anything else, `OK` included, with `UNKNOWN`:

`CHAIN_MISSING`, `BAD_ORIGIN`, `BAD_SIGNATURE`, `BROKEN_LINK`, `EXPIRED`, `RID_MISMATCH`, `BINDING_MISMATCH`,
`REPLAY`, `PATH_NOT_ALLOWED`, `SESSION_UNKNOWN`, `CLIENT_PATH_NOT_ALLOWED`, `INFLUENCE_MISMATCH`,
`INFLUENCE_DENIED`, `UNSAFE_SESSION`, `SCOPE_DENIED`, `UNCHECKABLE`, `PEER_MISMATCH`, `POLICY_EXPIRED`.

That is every [reason code](#reason-codes) except `OK` and the offline-only `TIME_MISMATCH`,
`PROMPT_MISMATCH`, `OUTSIDE_SESSION`, `PROOF_MISMATCH`, `RULES_MISMATCH` and `VERDICT_MISMATCH`.

## HTTP requests and responses

Only the Java SDK implements this section ([wire.md](wire.md#http-v3) has the headers). Inside a mesh there is no
handshake: its services pin one policy key, root and keyring in advance, and `sess` is `""`. Between
organisations there is one ([sessions-and-influence.md](sessions-and-influence.md#over-http)), and the partner
verifies as below with these inputs.

**A request, at the receiver.** The receiver runs the live order, 0 to 12, with `receiver` = its own name,
`receiverInRoute = true`, `expectedBind` = the HTTP binding of the request received, over the raw path and query,
`influence` = `X-Path-Influence` (`[]` when absent), `proof` = `X-Path-Proof` and
`nonceKey = <rid>|<last svc>|req`. A header that is present but does not decode is left to the check that reads
it: an unreadable chain is `CHAIN_MISSING`, unreadable influence is `INFLUENCE_MISMATCH`, and an unreadable proof
is no proof, so `PATH_NOT_ALLOWED`. A receiver MUST NOT drop influence it can't read, even when it does not
verify: dropping it could hide `private` content from the rule. It is answered
`400 {"reason":"INFLUENCE_MISMATCH"}` wherever verification has not refused the request first, in audit mode too
([Modes and refusals](#modes-and-refusals)). An origin starts a new request tree, so it carries neither the chain
nor the influence a request brings, and has nothing to drop.

**At a partner, in an attested session.** The verifier is the session's own: its config is the keyring and root
the client presented in the handshake, pinned under the client policy key the partner pinned, with `sess` = the
session id, the client's allowed origins, and the partner's own windows and nonce cache. A keyring or root past
its `notAfter` at the handshake makes the session unsafe
([sessions-and-influence.md](sessions-and-influence.md#status)), so no verifier is built on it; and once the
session's material expires, every call in it is `POLICY_EXPIRED`. The inputs are the same as above, with
`receiver` = the partner's entry service, `receiverInRoute = true` and `peer` the authenticated client, who MUST
be the boundary stamp's signer. The chain is one stamp, `prev` is `""`, and `expectedBind` and `influence` are of
the request and the entries received. The session is the one `X-Path-Session` names, and only when the peer it was
opened by, the certificate's issuer and name, is this call's
([sessions-and-influence.md](sessions-and-influence.md#over-http)). In an unsafe session there is no verifier and
nothing is verified. All sessions share one nonce cache, keyed as above.

**The peer under mTLS.** When the request came with a client certificate the TLS layer verified, the receiver
passes it as `peer`: `peer.svc` is the certificate subject's common name when it has exactly one, and `""`
otherwise, so a certificate with none or several fails check 12 (`PEER_MISMATCH`) rather than picking one;
`peer.inst` is the TCP address the connection came from. With no client certificate there is no peer.

So, for the peer check, a service's client certificate:

- MUST be issued by a CA the receiver's TLS layer trusts to name that organisation's services, since the
  receiver takes the name it carries as authenticated;
- MUST carry the service's name, exactly as the keyring names it, as the subject's only common name (OID
  2.5.4.3), and that value MUST be a UTF8String or a PrintableString. Nothing else in the certificate is read for
  it, not a subjectAltName nor the organisation.

The receiver reads `peer.svc` from the subject exactly as the certificate encodes it: the subject's DER bytes
within the certificate's `TBSCertificate`, which are the bytes the CA's signature covers. It MUST NOT read it from a
string rendering of the subject, nor from a subject its X.509 library has parsed and encoded again, since a
re-encoding can make a subject the steps below refuse look well formed. Implementations that follow these steps
read the same name from the same certificate:

1. **Finding the subject.** The `TBSCertificate`'s encoding is one `SEQUENCE` (identifier octet `0x30`) with
   nothing after it. Within it the receiver passes over, in order: the version, present exactly when the first
   identifier octet is `0xA0` (`[0] EXPLICIT`); the serial number, `0x02`; the signature algorithm, `0x30`; the
   issuer, `0x30`; and the validity, `0x30`. The next element is the subject, `0x30`. Each element passed over is
   checked by its header alone: its identifier octet MUST be exactly the one given, and its length MUST be
   definite, in its shortest form, and within the `TBSCertificate`. What those fields hold, and whatever follows
   the subject, is not read. A `TBSCertificate` that cannot be walked this far gives `peer.svc = ""`.
2. **The subject's shape.** The subject MUST be a well-formed DER `Name`, or `peer.svc` is `""`. Its contents are
   only RDNs, each a non-empty `SET` (`0x31`); an RDN's contents are only attributes, each a `SEQUENCE` (`0x30`);
   and an attribute's contents are exactly an `OBJECT IDENTIFIER` (`0x06`) and one value element, of any
   identifier. Every one of these headers, the subject's own included, MUST have a definite length in its shortest
   form (X.690's distinguished encoding) that stays within its parent. A value's identifier may be in the
   high-tag-number form, whose tag-number octets run up to and including the first with its top bit clear. These
   headers are the only ones checked: nothing inside a value is walked, so what another attribute's value holds,
   however it is encoded, is never looked at.
3. **Counting.** An attribute is a common name exactly when its `OBJECT IDENTIFIER`'s contents octets are
   `55 04 03` (2.5.4.3). Those contents are not otherwise checked: any other contents, malformed ones and other
   spellings of 2.5.4.3 included, make some other attribute. The common names are counted across every RDN, each
   value of a multi-valued RDN on its own, so `CN=a+CN=a` and `CN=a,CN=a` are two. A value of any type counts.
   Unless there is exactly one, `peer.svc` is `""`.
4. **The value.** That one value's identifier octet MUST be exactly `0x0C` (UTF8String) or `0x13`
   (PrintableString), and its contents well formed for that type: a UTF8String's are UTF-8 (RFC 3629), and a
   PrintableString's are only X.680's printable characters (letters, digits, space and `'()+,-./:=?`). Any other
   identifier gives `peer.svc = ""`, a constructed form such as `0x2C` and a high-tag-number form included, as do
   TeletexString, UniversalString, BMPString, IA5String and GeneralString. So does a value not well formed for its
   type. UTF8String and PrintableString are the two encodings of a DirectoryString that RFC 5280 requires
   conforming CAs to use (§4.1.2.6 for the subject, as §4.1.2.4 for the issuer), so a receiver needs no decoding
   of its own for the others, which survive only for older names. The receiver deliberately declines
   §4.1.2.6(c)'s SHOULD, that certificate users be prepared to receive TeletexString, BMPString and
   UniversalString: here those name no service.

A TLS stack may itself refuse, at the handshake, a certificate these steps would refuse. An implementation whose
stack does so also fails closed, consistently with this rule: no request then comes with a client certificate the
TLS layer verified.

`peer.svc` is the value's text as it is, compared with the last signer's `svc` exactly, with no case folding or
other normalisation.

A certificate is issued per service, not per instance, which is why `peer.inst` comes from the connection and not
from the certificate.

A partner also binds each session to the peer that opened it: the certificate issuer's distinguished name and the
service the certificate names ([sessions-and-influence.md](sessions-and-influence.md#over-http)). The issuer is
compared as text, in RFC 2253 form, so issuers are told apart by name, not by the CA's key. Only the partner that
recorded it compares it, so two implementations need not write it byte for byte alike, but one partner MUST write
it the same way every time. A certificate whose issuer name is empty, or that names no single service, opens no
session and matches none.

The caller authenticates the receiver the usual way: it checks the server's certificate against the host it
connects to (TLS hostname verification, RFC 9110 §4.3.4). That is why a response is checked with no peer (below).

**Who attests.** In either [mode](#modes-and-refusals), a service attests a response only when the request's chain
passed the live order, 0 to 12, at that service, as for a request at the receiver above: its own pinned material,
`receiver` = its own name, the request's proof and influence, and the peer when there is one. This holds whether or
not the service refuses requests that fail: one that does not enforce MUST still run the live order before it
attests, and a failure there only withholds the attestation. A response stamp is shaped like a request stamp, so
attesting a chain nobody checked would let anyone mint stamps under the service's key: on a forged one-stamp chain
with an empty `sig`, the response is a valid origin stamp from the answering service. So a service with nothing to
verify with never attests, and an origin, which starts each request tree afresh, never attests. Nor is a refusal
attested, or a request that failed in audit mode. A service runs the live order at most once per request, since it
spends the request's nonce key.

**A response, at the caller.** The caller checks `X-Path-Response` with `stamps` = the chain it sent then the
response stamp, `receiver` = its own name, `receiverInRoute = false`, `proof` = the proof it sent,
`influence = []`, `nonceKey = <rid>|<target>|resp` and no peer. In order:

1. The header is present and reads from its token ([wire.md](wire.md#http-v3)) as an object with exactly a `stamp`
   and an array of well-formed `labels` (`CHAIN_MISSING`).
2. The response binding of `resultHash`, the request's `rid` and the labels can be computed
   (`BINDING_MISMATCH`).
3. The live order, 0 to 11, with `expectedBind` = that binding. The sent chain's last `rcv` is the target, so
   check 4 requires the response stamp to be the target's; the route is the request's own, so the proof the
   caller sent proves it.

No peer is passed, because TLS hostname verification already authenticated the server as the target, and the
receiver check ties the stamp to it. The labels count as influence only when the whole response verifies: each
becomes an entry with `src = "http:<target>"` and `h = resultHash`. Any other response, whether unattested,
failing or a refusal, counts as one `local-untrusted` entry with the same `src` and `h`, and is never dropped.

## Modes and refusals

A service that verifies requests does so in one of two modes. Nothing else is a mode.

| Mode | On a result other than `OK` |
|---|---|
| `enforce` | The service refuses the request with the result's code. |
| `audit` | The service runs every check, refuses nothing and reports the result: the request is served, but not as verified. Its chain is not taken as having passed the live order here, so its response is not attested, no boundary stamp is signed over it, and it cannot write a [trusted record](sessions-and-influence.md#trusted-records). |

A service that cannot tell which mode it is in MUST enforce, so that a mistake in its configuration fails closed.

**Reporting the result.** In either mode a service MAY send its responder an [event](wire.md#events) for each
result other than `OK`, with `audit: true` in audit mode. An audit event is never
[attributable](wire.md#the-event), so a responder learns from it but does not act on it. Over MCP, an audit-mode
server also puts `"audit": true` in the verdict of the call's `paztport/verdict` ([wire.md](wire.md#mcp-v3)), and a
client does not read that as a refusal ([the verdict rule](#the-mcp-server-and-client)).

**The one exception.** In audit mode, a request whose influence does not parse is still refused, with
`400 {"reason":"INFLUENCE_MISMATCH"}`, and is not served. A receiver MUST NOT drop influence it can't read
([HTTP requests](#http-requests-and-responses)), in any mode, and serving the request without that influence would
hide `private` content from [the owner-aware rule](sessions-and-influence.md#the-owner-aware-rule). In enforce mode
verification has refused such a request already: check 9 fails, if nothing before it does.

**Attestation.** Neither mode changes who attests ([Who attests](#http-requests-and-responses); over MCP,
[the server decision](sessions-and-influence.md#the-server-decision)). A response is attested only when the
request passed the live order at that service. So in audit mode a request that failed is served, but its response
is not attested, and its caller counts it `local-untrusted`. A service that attests but does not verify requests
under a mode still runs the live order, once per request, before it attests; a failure there only withholds the
attestation.

**Outside the modes.** How a deployment turns Paztport off on a hop is not part of the protocol. A hop that is off
verifies, attests and reports nothing. Its callers count its responses `local-untrusted`, as any unattested
response, so turning a hop off can only add caution downstream, never vouch for anything. It cannot be an egress
([sessions-and-influence.md](sessions-and-influence.md#between-organisations)).

**What a refusal carries.** A refusal is for the caller, so it can decide what to do next. Attribution is for the
operator and the responder, and travels only in the service's own logs and in signed events. So a refusal MUST
carry `reason`, the code, and MUST NOT carry attribution (`suspectSvc`, `suspectInst`) or any other member. The
suspect is usually the caller itself, and telling it would tip it off before the responder acts. A refusal has no
`rid` either, since the caller already holds it. This holds in a mesh and at the boundary alike.

| Transport | A refusal |
|---|---|
| HTTP | Status `403`; or `400` for influence that does not parse where verification has not refused the request first, which is in audit mode ([the one exception](#modes-and-refusals)) or at a service that verifies no requests ([HTTP requests](#http-requests-and-responses)). Either way with `Content-Type: application/json`, which MUST carry no parameters, and the body `{"reason":"<code>"}`, sent as UTF-8: one JSON object whose only member is `reason`, a string, written with no whitespace, so that every implementation sends the same bytes for the same code. A reader MUST ignore any media-type parameter, `charset` included, and read the body as its [wire bytes](wire.md#reading), which are UTF-8 as [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259#section-8.1) §8.1 requires of JSON exchanged between systems; the `application/json` registration defines no `charset` parameter (§11). A body that does not read, or has any member but `reason`, gives no reason. The handshake endpoint's own errors, `400 {"error":"<code>"}` ([sessions-and-influence.md](sessions-and-influence.md#over-http)), answer a handshake, not a call, and are not refusals. |
| MCP ([profile](README.md#the-mcp-profile)) | A result with `isError: true` and `_meta["paztport/verdict"]` the token of `{ "reason": "<code>" }` ([wire.md](wire.md#mcp-v3)). An audit verdict adds `"audit": true`, and is not a refusal: the tool ran. |

## Offline verification

A record set, such as a client's evidence file, can be verified again later with no clock to be fresh against.
The offline verifier runs the live checks in the live order, with these differences:

| # | Offline |
|---|---|
| 0 | Not run against a clock. Keyring and root lifetimes are judged per record instead, at the record's own signed time, as each kind below says: a root or keyring counts only for a record no later than its `notAfter`. |
| 3, 4 | With `signers`, for a chain that never leaves one process (a local step, [MCP profile](README.md#the-mcp-profile)): the origin MUST report the expected instance (`BAD_ORIGIN`), and each stamp MUST be by the expected service and instance (`BAD_SIGNATURE`). |
| 5 | Every stamp carries the `rid` the record files it under, which defaults to the origin's (`RID_MISMATCH`). |
| 7 | In place of freshness: the last stamp's `ts` equals the time recorded with it, and when the run's records give start times, the origin's `ts` is one of them (`TIME_MISMATCH`). With age limits, the last stamp is at most `RUN_MAX_AGE_MS` after the origin and the origin at most `CALL_MAX_AGE_MS` after the last stamp (`EXPIRED`). Then the origin binds the run's recorded prompt (`PROMPT_MISMATCH`); a run with no prompt, or a disputed one, fails. |
| 10 | The nonce key has not been spent anywhere in the record set (`REPLAY`). A live cache that forgets after its window can't show that. |
| 12 | There is no peer offline. |

Each kind of record is checked this way:

- **A recorded call**: the server-side call check above, with the offline chain verifier, the age limits and the
  time the calling hop recorded stamping it. A chain that verifies but names a different call id from the
  record's is `RID_MISMATCH`. The call counts in its session only up to the session's limits, judged at the last
  stamp's `ts` (see the handshake below). A call that otherwise verifies, in a session whose recorded handshake is
  attested, but whose last stamp's `ts` is past one of the session's limits
  ([sessions-and-influence.md](sessions-and-influence.md#recorded-handshakes)), is `OUTSIDE_SESSION`.
- **A recorded response**: the client-side response check, with the live chain verifier at the time the client
  recorded verifying it, and one nonce cache that never forgets across the record set. Its `receiver` is the
  recorded call's verified last signer, the client that made the call. Check 0 runs at that time, with the
  `policyNotAfter` the client used: the earliest `notAfter` of the server's root and, in the entry-key form, its
  keyring. So a response recorded after the server's material expired is `POLICY_EXPIRED`.
- **A recorded local step** ([MCP profile](README.md#the-mcp-profile)): first, the step binds its call and
  decision: the `decision` token MUST read as a [decision](wire.md#bindings), and its `callId` MUST be the
  step's; a decision that does not read, or one for another call, is `BINDING_MISMATCH`, as is a binding that
  differs from the one the stamp signed. Then the offline chain verifier with `signers`
  (the origin service then the client hop, both on the client's one instance), `sess = ""`, the client's root and
  keyring, and `nonceKey = <rid>|<callId>|local`. Then, at the step's `ts`, the client's root and keyring are no
  later than their `notAfter` (`POLICY_EXPIRED`). Then the route verdict and proof the client recorded for the step
  MUST be what its chain proves (`PROOF_MISMATCH`); the `rulesHash` the step signed MUST be the client's
  (`RULES_MISMATCH`); and the decision it signed MUST be the one re-derived from those signed rules
  (`VERDICT_MISMATCH`).
- **A recorded handshake**: attested only when the request and the reply read from their tokens
  ([sessions-and-influence.md](sessions-and-influence.md#recorded-handshakes)), the reply is attested and verifies
  against the pin, both roots verify against their sides' policy keys, and the client keyring's signature verifies.
  It is judged at the time of each call that relies on it: a root or keyring, on either side, counts only up to its
  `notAfter`, as the reply certificate does
  ([sessions-and-influence.md](sessions-and-influence.md#recorded-handshakes)). A response relies on it too, but is
  limited only by the server's root window and, in the entry-key form, the server keyring's; the client's windows
  and the certificate do not limit it.

Each of these times is one the client signed (the last stamp's `ts`, which must equal the time recorded with it),
or for a response one the freshness window ties to the server's signed stamps. A verifier relies on them as it
relies on every recorded time. No edit to a record moves a `notAfter`, because the policy key's signature covers it.

## Reason codes

| Code | Given by | Meaning |
|---|---|---|
| `OK` | live, offline | Every check held. |
| `CHAIN_MISSING` | live, offline | No chain, or one that does not parse, or a malformed transport field around it, a response attestation that does not read included. |
| `BAD_ORIGIN` | live, offline | The origin is not an allowed origin (or, offline, not the expected instance). |
| `BAD_SIGNATURE` | live, offline | A field holds `\|`, a key is unknown, or a signature fails. |
| `BROKEN_LINK` | live, offline | A `prev` does not match. |
| `EXPIRED` | live, offline | Outside the freshness window, or offline, outside the age limits. |
| `RID_MISMATCH` | live, offline | The stamps don't share the `rid`, or name another request. |
| `BINDING_MISMATCH` | live, offline | A `rcv` names the wrong hop, or the binding does not match what was received. |
| `REPLAY` | live, offline | The nonce key was seen before. |
| `PATH_NOT_ALLOWED` | live, offline, client local | The route is not proven against the root. Also the local gate's verdict for a tool its route list doesn't have. |
| `SESSION_UNKNOWN` | live, offline | A stamp names another session. Over HTTP, also a call whose `X-Path-Session` names no live session opened by the sending peer. |
| `INFLUENCE_MISMATCH` | live, offline | The influence does not parse, or the last stamp does not commit to it. |
| `PEER_MISMATCH` | live | The authenticated transport peer is not the last signer. |
| `POLICY_EXPIRED` | live, offline | The keyring or root the verifier relies on has expired. Live: `now` is past `policyNotAfter`. Offline: the record's own time is past the `notAfter` of a root or keyring it relies on. Names no one. |
| `TIME_MISMATCH` | offline only | A stamp's time is not the one recorded with it. |
| `PROMPT_MISMATCH` | offline only | The origin does not bind the run's recorded prompt. |
| `OUTSIDE_SESSION` | offline only | A recorded call that otherwise verifies, in a session whose recorded handshake is attested, but whose last stamp's `ts` is past one of the session's limits ([recorded handshakes](sessions-and-influence.md#recorded-handshakes)). |
| `PROOF_MISMATCH` | offline only | A recorded local step ([MCP profile](README.md#the-mcp-profile)) whose recorded route verdict or proof disagrees with what its chain proves. |
| `RULES_MISMATCH` | offline only | A recorded local step ([MCP profile](README.md#the-mcp-profile)) whose signed `rulesHash` is not the client's. |
| `VERDICT_MISMATCH` | offline only | A recorded local step ([MCP profile](README.md#the-mcp-profile)) whose decision, re-derived from the signed rules, differs from the one it signed. |
| `CLIENT_PATH_NOT_ALLOWED` | server decision | An MCP server's name ([MCP profile](README.md#the-mcp-profile)) for `PATH_NOT_ALLOWED` against the client's policy. |
| `INFLUENCE_DENIED` | server decision, client local | The influence rule refused a public write. |
| `UNSAFE_SESSION` | server decision | The tool is disabled in an unsafe session. |
| `SCOPE_DENIED` | client local ([MCP profile](README.md#the-mcp-profile)) | The local gate: a path or program outside the signed rules. |
| `UNCHECKABLE` | client local ([MCP profile](README.md#the-mcp-profile)) | The local gate could not tell what the call would touch. |

"Live" codes come from a live verifier, and "server decision" codes from a server's decision on a call; both
are valid verdicts for a server to send. "Offline only" codes are never sent live, and a client MUST NOT accept
them as a server's verdict. "Client local" codes come from the client's own gate for its local tools. A server
has no reason to send them, but the client's verdict check keeps them, since they are not offline-only
([the verdict rule](#the-mcp-server-and-client)).

## Receiving an event

A responder checks each body sent to it as an [event](wire.md#events), with these inputs, all from its own
configuration, never from the event:

| Input | Meaning |
|---|---|
| `allowedSigners` | The services that may send it events. |
| `keyring` | Service name to public key. A key is looked up by own name only, as for the live order. |
| `now` | The responder's clock, in ms since the Unix epoch. |
| `seen` | The ids it has accepted, each with the `now` it was accepted at. |

It runs these checks in this order, and the first that fails is the refusal. A refused event takes no decision
and changes nothing, `seen` included.

| # | Check | Refusal |
|---|---|---|
| 1 | The body is the JCS bytes of an object whose `signer`, `payload` and `sig` are strings and which has no other member, read as [wire bytes](wire.md#reading) ([the envelope](wire.md#the-envelope)). | `MALFORMED_ENVELOPE` |
| 2 | `signer` is in `allowedSigners`. | `SIGNER_NOT_ALLOWED` |
| 3 | `keyring` has a key for `signer`. | `UNKNOWN_SIGNER` |
| 4 | `sig` decodes as base64url, and verifies under that key over the signed bytes. | `BAD_SIGNATURE` |
| 5 | `payload` decodes as base64url to [an event](wire.md#the-event): the JCS bytes of an object with each of the event's members of its type and no other member, read as [wire bytes](wire.md#reading), so an overlong form, an encoded surrogate or whitespace around the object is malformed. The one exception is an absent or `null` `eventId`, which is left to check 6; an `eventId` that is present otherwise MUST be a string. | `MALFORMED_EVENT` |
| 6 | `eventId` is present, and is neither `null` nor `""`. Any other string is an id. | `NO_EVENT_ID` |
| 7 | `ts` is at most `EVENT_WINDOW_MS` from `now`, either way: \|`now` − `ts`\| ≤ `EVENT_WINDOW_MS`, computed exactly, with no overflow. | `OUTSIDE_WINDOW` |
| 8 | `eventId` is not in `seen`. It is then added, at `now`. | `REPEATED_EVENT_ID` |

Otherwise the event is accepted.

| Constant | Value | Meaning |
|---|---|---|
| `EVENT_WINDOW_MS` | `30000` (30 s) | How far an event's `ts` may be from `now`, either way. |
| `EVENT_ID_TTL_MS` | `60000` (60 s) | How long `seen` keeps an id after accepting it. It MUST be at least 2 × `EVENT_WINDOW_MS`. |

Why this order:

- **The allow-list before the keyring.** A name not on it is the sender's own text, so it is never looked up.
  A responder that logs a refusal names the signer only once check 2 has passed, when it is a name from its own
  configuration.
- **The signature before the payload is read.** Nothing past the envelope is read until an allowed key has
  signed it, so a malformed event can only come from an allowed signer.
- **`seen` last.** An id is added only when every other check has held, so a forged, stale or malformed body
  cannot spend an id the real signer will use.
- **Twice the window.** An event's `ts` is acceptable from `ts − EVENT_WINDOW_MS` to `ts + EVENT_WINDOW_MS`, so
  an id kept for 2 × `EVENT_WINDOW_MS` after it was accepted is still in `seen` for as long as a replay of it is
  fresh. Once it is forgotten, a replay is `OUTSIDE_WINDOW`.

`seen` is one per responder, across all its signers, and keyed by `eventId` alone. A refusal's name is for the
responder's own log; the sender is told only that the event was refused
([Carrying an event](wire.md#carrying-an-event)).

| Refusal | Meaning |
|---|---|
| `MALFORMED_ENVELOPE` | The body is not an envelope. |
| `SIGNER_NOT_ALLOWED` | The signer is not one the responder takes events from. |
| `UNKNOWN_SIGNER` | The signer is allowed, but the keyring has no key for it. |
| `BAD_SIGNATURE` | The signature does not decode, or does not verify. |
| `MALFORMED_EVENT` | The signed payload is not an event. |
| `NO_EVENT_ID` | The event has no id. |
| `OUTSIDE_WINDOW` | The event's `ts` is more than `EVENT_WINDOW_MS` from `now`. |
| `REPEATED_EVENT_ID` | The responder has already accepted an event with this id. |

`events.json` pins these in `verify`:

- **Accepted:** an event, an audit event, and an `eventId` of a single space.
- **The window:** `ts` at `EVENT_WINDOW_MS` from `now` and 1 ms past it, on both sides, and 2^53 − 1, which is a
  protocol integer but outside the window.
- **`seen`:** a replay (`uses` = 2), a new payload under a spent id, an id still in `seen` while its `ts` is
  fresh, a replay after the window, and a bad signature and a stale event that spend no id.
- **Malformed envelopes:** not JSON, empty, an array, `null`, a bare event, a missing `sig`, a `null` signer,
  a number as `signer`, `payload` or `sig`, another member, trailing text, a second value, a byte order mark and
  whitespace around the body.
- **Signers and signatures:** a signer not allowed, before its signature is looked at; an allowed signer with no
  key; a wrong signer's key, a tampered payload, a signature made without the prefix, and a `sig` that is not
  base64url.
- **Malformed payloads:** not base64url; not UTF-8, an overlong form and an encoded surrogate; a byte order
  mark; not JSON, not an object, trailing text and another member; a missing `reason`, `ts` or `audit`; `null`
  as `reason`, `suspectSvc`, `suspectInst`, `rid` or `ts`; a number as `reason`, `suspectSvc`, `suspectInst`,
  `rid`, `audit` or `eventId`; a string as `ts` or `audit`; whitespace around the payload; a `ts` with a fraction,
  written `1767225600000.0` or `1.7672256E12`; and a `ts` of 2^53, −(2^53 − 1), −2^53 and −2^63.
- **`eventId`:** missing, `null` or empty, refused.
- **The order:** a bad signature before a payload that is not base64url and before one that is not JSON; a bad
  signature before the window; a malformed event before a missing id; a missing id before the window; and the
  window before `seen`.

## Guidance for a responder

A responder acts on rejections, for example by isolating the named instance.

- **Only events it accepted, and only attributable ones.** Anyone can send a responder a body, so it acts only
  on an event that passed [Receiving an event](#receiving-an-event). A responder MUST NOT act against a suspect
  on an event that is not [attributable](wire.md#the-event); the rest of this list explains why.
- **Only attributable rejections are triggers.** `INFLUENCE_DENIED` and `UNSAFE_SESSION` are about content and
  capability, not compromise: an honest component misled by poisoned input gets them. A responder MUST NOT
  quarantine on them. It SHOULD log them. The same holds for the client-local codes, and for `POLICY_EXPIRED`,
  which is about the verifier's own configuration: every honest caller gets it once the verifier's policy
  expires, so it is never attributable, and the policy owner, not the responder, is the one to act.
- **Act only on a named suspect.** A result with empty suspect fields names no one, by design: acting on it
  would let a forged chain point at anyone.
- **Under mTLS, `suspectInst` is the transport peer's address.** The responder resolves it to an instance on
  its own network; the address is the transport's evidence, not the chain's.
- **Keep the instance check.** A certificate is issued per service, so the peer proves the service, not the
  instance; and without a peer, `suspectInst` is the signer's own claim. Before acting, a responder MUST check
  that the instance it resolved runs the service named in `suspectSvc`.
