# TypeScript SDK

An npm workspace of three packages. Node 22.19 or newer runs the `.ts` sources
directly, with no build step. Nothing is published: the agents demo
([poc-demos/agents-mcp](../../poc-demos/agents-mcp/README.md)) links the packages
with `file:` paths, and they resolve their own dependencies from this workspace,
so install it first.

```bash
npm install
npm run check   # tsc, for the type-level guards that vitest does not check
npm test
```

One test reads a keyring written by the Java keygen, from `PAZTPORT_JAVA_KEYRING`
or else the Java demo's `out/keys/keyring.json`. With neither it skips; `./run test`
writes one and names it, so there it always runs.

| Package | What it holds |
| --- | --- |
| [`@paztport/core`](#paztportcore) | The protocol, with no transport. |
| [`@paztport/mcp`](#paztportmcp) | The MCP transport on top of core: the `tools/call` binding, the client side and the server side. |
| [`@paztport/policy-tool`](#policy-tool) | `paztport-keygen` and `paztport-policy`, which write the keys, keyrings, roots and proof bundles the other two read. |

A server checks a received `tools/call` with `verifyCall`. `params` is the call's params object as received;
`keyrings`, `roots`, `sess` and `policyNotAfter` come from the server's own pinned policy material, and `extensions`
names the extensions it acts on:

```ts
import { NONCE_TTL_MS, NonceCache, extensionSettings } from "@paztport/core";
import { verifyCall } from "@paztport/mcp";

const nonces = new NonceCache(NONCE_TTL_MS);   // remembers the nonce keys spent
const extensions = extensionSettings(["influence"]);   // throws on a name that is not an extension name
const config = {
  keyrings, roots, allowedOrigins: ["session"], sess, nonces, now: Date.now(), policyNotAfter, extensions,
};
const checked = verifyCall(params, { serverId: "github" }, config);
if (!checked.result.ok) throw new Error(checked.result.reason);   // a reason code, such as BINDING_MISMATCH
// checked.result.handOver: for each extension in actsOn, one { svc, items } per stamp, and only when the call verified
```

`verifyCall` derives the receiver (`mcp:github.<tool>`), the binding and the nonce key itself, and never throws.

## @paztport/core

The protocol, with no transport: base64url, Ed25519 and SHA-256 helpers, canonical JSON, version 4 stamps and
chains, the blocks that carry extensions' claims, the salted Merkle tree, signed roots and keyrings, reply
certificates, policy building, reason codes, the replay cache, prompt binding, sessions, local tool rules and the
verdict for a local tool call, local steps, the live chain verifier (`verifyChain`), the extension `influence`, and
`keyFileText`, which trims a key file's text of the JSON whitespace around it and nothing else. For responders,
`signEvent` signs an event, `createEventVerifier` checks a received body (strictly: the envelope and payload must be
JCS bytes) and `isAttributable` says whether the responder may act on it. Offline verification of a recorded run
(`verifyChainOffline`) is here too, and shares its checks with the live verifier; the agents demo's `npm run verify`
uses it.

It implements protocol version 4, as the [spec](../spec/README.md) defines it, for MCP only, and replays
[`v4.json`](../spec/README.md#v4json). The TypeScript SDK has no HTTP binding and no delivery key (the Java and Go
SDKs have both), and it neither names nor confirms operations over HTTP, nor reads their keys (the Java SDK does all
three; the Go SDK names operations and reads their keys, but does not confirm them). Its verifier does accept an
operation in an `rcv`.

- **Version 4 only.** `STAMP_VERSION` is 4, and the live and offline chain verifiers take version 4 stamps only: a
  chain holding a stamp whose `v` is anything else is malformed, `CHAIN_MISSING`.
- **Tokens in, tokens out.** The SDK has no JSON library: it reads every Paztport object from bytes with its
  own strict reader, and writes it as its JCS bytes ([wire.md](../spec/wire.md#json)). `writeToken` writes an
  object's token, the base64url of those bytes, and `readToken` reads one; `readWireBytes` reads wire bytes,
  `readFile` a file, and `printFile` writes the file format.
- **Readers.** The three readers throw `MalformedJson`, naming the reading `step`, for bytes they refuse. Each
  object has a reader that takes its token and refuses anything but exactly its members: `readChain`,
  `readProof`, `readBlocks`, `readAttestation`, `readLocalDecision`, `readSessionRequest`, `readSessionReply`,
  `readKeyring`, `readRoot` and `readLocalRules`, and for files `readKeyringFile`, `readRootFile`,
  `readReplyCertFile`, `readProofBundleFile` and `readLocalRulesFile`.
- **Blocks.** A block holds one stamp's items by extension name and the extensions its signer requires of the next hop
  ([wire.md](../spec/wire.md#blocks)). `makeBlock(items, requires)` builds one, sorting `requires` and throwing on a
  name that is not an extension name or on a name twice in `requires`; `EMPTY_BLOCK` attaches nothing. `commitBlock`
  gives a stamp's `ext`: `""` for the empty block, else the base64url of the SHA-256 of its JCS. `readBlocks` reads a
  token of blocks. `itemsUnder(block, name)` gives the items a block holds under a name, or null when it does not name
  it; it finds only the block's own members, so a name such as `constructor` finds nothing where it is not listed.
- **Extension settings.** A verifier's config takes the extensions it acts on and the names it carries as one
  `ExtensionSettings`, built by `extensionSettings(actsOn, allowed?)`, or for a recorded response by
  `recordExtensionSettings`, never by hand. `extensionSettings` throws on a name that is not an extension name, and on a
  name in `actsOn` that `allowed` does not hold, so a verifier never meets settings that break the rule of
  [Inputs](../spec/verification.md#inputs). `NO_EXTENSIONS` acts on none and carries any name.
- **The verifier's inputs.** `verifyChain` takes the tokens as received: the chain, the blocks (null for no token, which
  is one empty block per stamp) and the proof, so a token that does not read is the typed rejection of the check that
  reads it; so do `verifyResponse` for an attestation and `checkSessionReply` for a reply. Its config is the pinned
  keyrings and roots, `allowedOrigins`, `sess`, the nonce cache and key, `now`, `policyNotAfter`, the age limits when
  they are not the defaults, and `extensions`. It runs the live order, checks 0 to 12, and never throws for anything in
  its input.
- **The hand-over.** On `OK` a verification carries `handOver`: for each name in `actsOn`, one `{ svc, items }` per
  stamp in chain order, with `items` null where the stamp's block does not name the extension; on any other result
  it is null. The SDK builds no hand-over "as not verified"
  ([the live order](../spec/verification.md#the-live-order)): its only transport is MCP, where an audit-mode server
  that runs a call that failed verification reaches no decision that reads items
  ([What the rules read](../spec/influence.md#what-the-rules-read)), and an unsafe session hands nothing on.
- **The receiver.** Every stamp names the hop it was handed to, and the verifier checks each `rcv` against
  the next stamp and the last against `receiver`. An `rcv` is a service's name or `svc#operation` (check 4
  accepts either for a hop's next service, and takes the last `rcv` as exactly `receiver`). A live call or
  chain stamped for a different receiver is `BINDING_MISMATCH`, not a route failure, so a forwarded chain
  does not blame its last signer.
- **The peer.** `peer` (`{ svc, inst }`) is the sender a transport authenticated. Given one, the verifier checks it is
  the last signer (`PEER_MISMATCH`, check 10) before the nonce key is recorded, so a request sent again by another peer
  spends nothing, and names it as the suspect in every result but `POLICY_EXPIRED`. No transport in this SDK supplies
  one: the MCP wrappers (`verifyCall`, `verifyMcpResponse`, `McpServerSession.checkCall`) pass no peer, because stdio
  has no TLS, so for MCP over stdio check 10 is skipped, and the peer check is core's (`verifyChain`).
- **The replay cache.** `nonceKey(parts)` writes a chain's key as the JCS text of an array of strings, each written
  as RFC 8785 writes strings, so a call id holding a noncharacter has a key. `NonceCache` is a concrete in-memory
  class, and `VerifierConfig.nonces` takes that class rather than an interface: its `seenBefore` is synchronous
  and has no failure path, so a verifier in this SDK keeps its nonce keys in the memory of the process that runs
  it.
- **The policy's window.** A verifier config pins one or more keyrings (`keyrings`, each a `PinnedKeyring`)
  and roots (`roots`, each a `PinnedRoot`), each with its own `notAfter`, so a rollover can pin the old and
  the new together.
- **Live checks.** Live, only those current at `now` are used: a stamp verifies under any key the current keyrings
  give its service, and a proof against a current root with its `rootId`. A live config also requires
  `policyNotAfter`, the earlier of the latest keyring and the latest root `notAfter` (`pinnedNotAfter`); past
  it every chain is `POLICY_EXPIRED`, before the live order's checks.
- **Offline.** Offline, a keyring or root counts for a record no later than its `notAfter` (`Infinity` for
  none), and a record for which no keyring, or no root, counts is `POLICY_EXPIRED`. `verifyChainOffline` runs
  checks 9a and 9b and never 9c, which is live only. A recorded response is checked by the live verifier at the time
  the client recorded verifying it, with settings from `recordExtensionSettings(readAs, allowed?)`: as
  `extensionSettings`, but without check 9c, since the response was held to the caller's `actsOn` live and the
  record does not hold it.
- **Per-session verifiers.** Every live verifier here is per session, pinning that session's one keyring and
  root: the server's call check takes the client root's and `clientKeyringNotAfter` (`earliestNotAfter`), and
  the client's response check the server root's and, in the entry-key form, `serverKeyringNotAfter`
  (`serverPolicyNotAfter`).
- **Event verifiers.** `createEventVerifier` takes `keyrings` too, a non-empty array it copies at
  construction, and accepts a signer any of them has a key for.
- **Signed keyrings.** A keyring is signed by its policy key (`signKeyring`, `verifyKeyring`), and the session
  request carries the signature as `clientKeyringSig`, with the keyring's `notAfter` as `clientKeyringNotAfter`.
  A request without the signature, or with one that is `null`, not a string or empty, is malformed and opens no
  session (`InvalidParams`, JSON-RPC `-32602`). One whose signature is wrong is unsafe live and not attested
  offline.
- **Handshakes judge the windows, live.** `sessionStatus` takes the server's own keyring window and `now`, and
  opens a session unsafe when either side's root or keyring is past its `notAfter`, so a server whose own
  material has expired degrades to unsafe sessions. `verifySessionReply` (the client's live check) refuses the
  server's root, and in the entry-key form its keyring, when expired, as `BAD_SIGNATURE`.
- **Handshakes judged offline.** `isAttestedSession` checks a recorded handshake offline at the record's time:
  each root and keyring, on either side, counts only up to its `notAfter`.
- **A missing `notAfter`.** A root or keyring without a `notAfter` is malformed: `readRoot`, `readRootFile`
  and `readSessionRequest` refuse it, and `verifyRoot` and `verifyKeyring` never accept it.
- **Checking a record set.** `recordedSession` reads a recorded handshake: attested at a time, at all (at the earliest
  of its limits) and the `policyNotAfter` a response in it is checked with, undefined where the server's signatures do
  not verify, which check 0 refuses (`POLICY_EXPIRED`). `callInSession` limits a recorded call to its session
  (`OUTSIDE_SESSION`), `newRecordSet` holds a record set's spent keys and its response cache that never forgets, and
  `verifyRecordedLocalStep` checks a recorded local step ([the MCP profile](../spec/README.md#the-mcp-profile)) with its
  signers given. The agents demo's `verify` calls these four. A verifier that acts on `influence` judges a recorded call
  with `recordedCallReason` instead of `callInSession` alone: it reads the items once the offline order gives `OK`,
  before the session's limits, so a call past them that holds an item that does not read is `INFLUENCE_MISMATCH`.
- **The handshake's pieces.** `readSessionRequest` reads a request from its token, with exactly its members (a
  missing `clientKeyringSig` is refused, as in the Java SDK), `sessionRequest` and `replacementRequest` write
  one, and `buildSessionReply` answers it in the entry-key form, listing the extensions the server acts on, sorted,
  in either status. `readSessionReply` reads a reply from its token, and `checkSessionReply` is the client's check
  of a reply's token, given the extensions the client requires of the server, returning a `ReplyCheck`
  (`ATTESTED`, `UNSAFE`, `MALFORMED_REPLY`, `PIN_MISMATCH`, `BAD_SIGNATURE` or `EXTENSION_REQUIRED`). A service
  that loads its own keyring and root checks them with `checkOwnMaterial` and warns near their end with
  `expiryWarnings` (`WARN_WITHIN_MS`, `describeNotAfter`).
- **A client's requirement.** `requirement(extensions, continueWithout?)` builds what a client requires of a server,
  once: it refuses a name that is not an extension name, keeps each name once, sorted, and returns a frozen
  `Requirement`, the only kind `callsAfter` takes (`NO_REQUIREMENT` requires nothing). `callsAfter(check, listed,
  requirement)` is the rule for a client that requires extensions of a server
  ([sessions.md](../spec/sessions.md#the-clients-check-of-the-reply)), in one function, which the MCP client's
  `openSession` calls: given the first reply's check (null for a JSON-RPC error or a timeout) and the extensions the
  reply lists, it says whether the client makes calls and the `requires` its calls carry. Only an attested session
  whose reply lists every required name lets it make calls, unless the requirement's `continueWithout` switch is set,
  and then its calls carry no `requires` for a name it could not get.
- **The server's gate.** `decideServerCall` is the gate no extension decides: in an unsafe session, or with no
  handshake yet, the tools disabled when unsafe are refused, and every other call is allowed.
  `sanitiseVerdictReason` makes a server's refusal reason safe to show, since it reaches the model.
- **Stamping names.** `mintOrigin` takes the origin name as `svc`, which the policy and its receivers' allowed
  origins must carry too, and the block the origin commits to. `mintOrigin` and `stampToolCall` refuse a signing
  name or a receiver that is not a route node (`requireStampableNames`), since such a stamp could never verify, and
  `stampLocalStep` refuses a signing name that is not one (the tool in its `local:<tool>` receiver is data: an
  unlisted tool's refusal verifies without a route proof); `signStamp`, the low-level builder, does not, so a test
  can still build a bad stamp.

### The extension `influence`

`influence` ([influence.md](../spec/influence.md)) is a set of functions over the hand-over, in `core/src/influence/`.
The core's verifier imports none of them: a test pins that no file outside that folder, the local steps and the
package's exports imports from it, so the core's verifier carries influence's items without reading them.

- **What a request holds.** `entryOf` reads one item as an entry: an object with exactly a known `cls`, a string `src`
  and `h`, and an optional string `cid` and non-empty string `owner`, or it throws. `readRequestInfluence(stamps)` reads
  the items handed on under `influence`, one entry of the hand-over per stamp, each by `entryOf`: it gives the entries
  and whether every stamp names `influence`; or, when an item does not read as an entry, `INFLUENCE_MISMATCH` and the
  signer of the first block holding one, for the operator's log, since the code names no one. It is the one place
  that code is given for such an item: `influenceReason`, `decideVerifiedCall` and the recorded local step take it
  from there. `influenceReason` gives a verified request that code, and otherwise the verifier's reason.
- **The rules.** `guardedWriteRefused(everyStampNames, influence, destinationOwner?)` is the every-stamp rule, then
  the owner-aware rule, `publicWriteRefused`; the caller takes the destination's owner from its own records.
  `shapedOnlyByTrusted` says whether influence holds no untrusted content, the condition on the content for writing
  a trusted record.
- **The server's decision.** `decideVerifiedCall(stamps, opts)` is the decision of a server that acts on
  `influence` on a call that verified in an attested session: first every item must read as an entry
  (`INFLUENCE_MISMATCH`), then a write to a public destination is decided by `guardedWriteRefused` over the entries
  and the classes the server served in the session (`INFLUENCE_DENIED`); anything else is allowed.
- **What a response adds.** `labelOf` reads one item as a label: an object with exactly a known `cls` and a string
  `cid`, and an optional non-empty string `owner`, or it throws. `responseEntries(reason, stamps, src, resultHash)`
  turns a response over MCP into the entries a client that acts on `influence` adds: when the response check gave
  `OK` and every block of the response chain names `influence` with only labels under it, one entry per label, each
  read by `labelOf`; else exactly one `local-untrusted` entry, also for a result no check ran on (`reason` null, as in
  an unsafe session). Each entry has `src` `server:<serverId>` and `h` the result hash. The MCP client's
  `readToolResult` builds what a result adds with it, so an application never turns labels into entries itself.
- **Blocks.** `influenceBlock(items, requires?)` builds a block that names `influence` with the entries a hop adds
  or the labels a responder attaches, as written; `[]` names it with nothing to add.

`v4.json`'s member `influence` pins these functions: its replay calls `entryOf`, `labelOf`, `publicWriteRefused`,
`decideVerifiedCall`, `readRequestInfluence`, `responseEntries` and `recordedCallReason`.

## @paztport/mcp

MCP transport on top of core: the `tools/call` binding, the `_meta` keys (`paztport/chain`, `paztport/proof`,
`paztport/extensions` and `paztport/callId` on a call, `paztport/attestation` and `paztport/verdict` on a result,
each value but `paztport/callId`'s a token), the client side and the server side. A call names
`mcp:<serverId>.<tool>` as its receiver, and a response chain ends at the client that made the call. The
handshake's params are `{request}` and its result `{reply}`, each a token: `readSessionParams` reads the params into
a request and `sessionReplyToken` takes the reply token from a result, and a refusal's verdict is a token that
`readVerdict` reads.

**The client side.** `openSession` opens a session, given what the client requires of the server (`requirement`,
none by default). Its outcome is `attested`, with the `requires` each call's block carries; `unsafe`, a session the
client calls in unattested; or `no-calls`, a session in which its requirement lets it make no call, by
`callsAfter`. When the server may hold an attested session the client cannot use, it sends the replacement request
best effort, whether or not the client then makes calls; it does not after `EXTENSION_REQUIRED`, since the reply was
sound.

`stampToolCall` stamps a call: the chain, the route proof (`toolCallProof`), the blocks `[originBlock, block]` and
the call id. It always writes `paztport/extensions`, also when both blocks are empty, so the SDK sends one form, and
it throws when `originBlock` is not the block the origin stamp commits to, rather than leave the server to refuse
the call `EXTENSION_MISMATCH`. It takes the session's `requires`, the outcome's, and throws when `block.requires`
lacks one of them, so a call never drops, silently, what the client's requirement asks of the server.

`readToolResult` reads a result in the session it arrived in (`ResultContext`, which carries the client's
`ExtensionSettings` in an unsafe session as in an attested one): `refused` for a server's refusal, which means the tool
did not run; `malformed` for a result JCS cannot hash; `withheld` for a response whose last block requires an extension
the client does not act on (check 9c, `EXTENSION_REQUIRED`); and otherwise `read`, with the verification and what the
result adds to influence. The application MUST NOT hand a `withheld` result on: it fails the call and does not retry it,
since the tool ran. The context also carries `serverId`, the server's id from the client's configuration. For a client
that acts on `influence`, a `read` result in an attested or unsafe session, and a `withheld` one, which only an attested
session gives, carry `{ kind: "entries", entries, hash }`: the entries it adds to the client's influence, built by
core's `responseEntries` with `src` `server:<serverId>` and `h` the result hash, which is there too for the client's
record. That is an entry for each label of a response that verified and names `influence` in every block with only
labels under it, and otherwise one `local-untrusted` entry, as for a `withheld` result and every result in an unsafe
session. A `refused` result adds nothing, a `malformed` one carries no influence at all, and in a session that is `off`
(Paztport switched off) no result adds anything. A client that does not act on `influence` reads `{ kind: "none" }` in
every session. `verifyMcpResponse` is the response check `readToolResult` runs; a client re-checking a recorded response
passes the time it recorded verifying it as `now`, and settings from `recordExtensionSettings`.

**The server side.** `McpServerSession` takes the server's `ExtensionSettings` beside its policy and rules. Its replies
list the extensions it acts on, and everything it does for influence it does exactly when it acts on `influence`: the
item check and the decision on a guarded write, the label and `requires` on a response, and the classes it has served.
Without `influence` it attests with empty blocks, and past verification decides only by the unsafe-session list.
`handleToolCall`, which a server calls for each `tools/call`, checks the call's chain in an attested session; at a
server that acts on `influence`, decides a call that verified with `decideVerifiedCall`, sending the signer of a block
whose item does not read to its `warn`; then applies `decideServerCall`; refuses with `refusedToolResult` in enforce, or
notes the verdict on the result in audit; runs the tool, and attests the result of a call that verified. A verified call
whose hand-over lacks `influence` at a server that acts on it is a fault in this SDK, not in the call, so
`handleToolCall` throws rather than refuse it. The tool's `run` returns a `ToolRun`: its result and `cls`, the class of
the content it holds. A server that acts on `influence` adds `cls` to the session's served classes for every result it
returns in an attested session, whether or not the call verified, which in audit mode it may not have, and labels an
attested response with it; there it throws, after the tool has run, for a result without one, and in an unsafe
session it does not read it. A `null` session is a deployment with no Paztport material, so every call is in an
unsafe session. The decisions are core's, so a server in another transport decides the same.

`verifyRecordedCall` checks a recorded `tools/call` offline, with `verifyChainOffline`.

A server opens an attested session only for a client policy key in its `pinnedClientKeys`.
`McpServerSession` holds no policy private key: it answers handshakes in the
[entry-key form](../spec/sessions.md#the-reply), signed by its entry
service's key (`hops[0]`), with the `ServerPolicy`'s `keyringSig` and `replyCert`.
Its constructor refuses to start, through the exported `checkServerPolicy` (core's `checkOwnMaterial` for the
keyring and root, then this server's own checks), with a policy that does not hold together at the session's
clock, lifetime included: no `clientOrigins`, an empty list or a blank name in it; a keyring or root whose
`notAfter` is missing or not an integer, expired, or not signed by its policy key; a `signingKeys[hops[0]]` that is
not the entry's keyring key, or a `signingKeys[hops[1]]` that is not the tools hop's own keyring key; a route proof
for `hops[0]/hops[1]` that does not prove against the root; or a certificate that does not verify under its policy
key, names another service or key, or has expired. Material that is current but has 42 hours (a quarter of the
default lifetime) or less left is warned about once per item (keyring, root, certificate) at construction, naming
its `notAfter`, through the constructor's `warn` argument, `console.error` by default.

## policy-tool

`@paztport/policy-tool`: two command-line tools. `paztport-keygen` writes a
keypair per service, a policy keypair and a keyring signed by the policy key, valid for `--policy-days` days
(default 7). `paztport-policy` signs roots and re-signs the keyring, both valid for
`--policy-days` days (default 7), in one of two modes:

- **Rebuild**, `--paths <yaml> --policy-key <file> --keyring <keyring.json> --out <dir> [--depth 8]`: a new tree
  from the `paths.yaml`, so a new `root.json`, `rootId` and proof bundles, which every holder must reload
  together, and the keyring re-signed. Rebuild when the routes change.
- **Renew**, `--renew --policy-key <file> --keyring <keyring.json> --out <dir>`: the `root.json` in `--out` and
  the keyring signed again with a new `notAfter`, keeping the root's `root` and `rootId`, so the proof bundles
  (and any `rules.json`) stay valid and are not touched, and holders can pick up the renewed files one at a time.
  The new `notAfter` is the run's time plus `--policy-days`, so a renewal can shorten a longer existing window.
  It takes no `--paths` or `--depth`. Renewal is the routine operation, run well before `notAfter`; expired
  files are renewed all the same.

Either mode first checks that the keyring has a `notAfter` and verifies under the policy key it names, expired or
not, and that that key is the `--policy-key`; renewing also checks the root verifies under it. Any failure is
refused, exit 2, with nothing written, in a message that leads with the file at fault; the checks are core's
`renewKeyring`, `renewRoot` and `issueReplyCert`. A rebuild refuses a route node that is empty, `.` or `..`, or
holds `/`, `\`, `|` or a lone surrogate (core's `requireValidNode`, also called by `buildPolicy`), naming the
`paths.yaml` and the node. A rebuild vouches that the routes in the `paths.yaml` are the ones allowed now; a
renewal, that the existing tree's routes all still are, since narrowing a policy is a rebuild.
Re-signing the keyring vouches that each listed key is still its service's current key: the tool can check only
that this policy key signed the keyring before, so retiring a key, which needs a new keyring rather than a
renewed one, is the policy owner's to ensure. With `--reply-cert-svc <name> [--reply-cert-days 7]` either mode
also writes `reply-cert.json`, a [reply certificate](../spec/wire.md#the-reply-certificate) for that service's
key, its lifetime set apart from the policy's, refusing a service the keyring has no key for. A `paths.yaml` with
a `local:` block (folder rules, bound into the root as one more route and written to `rules.json`) needs
`--client-chain <svc,svc,...>`, the client's origin service and then its hops, which the rules route is pinned
under; there is no default, and a rebuild without it is refused. `paztport-policy` prints only file names, their
`notAfter` and the certificate's service.
