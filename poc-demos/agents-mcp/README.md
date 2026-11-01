# Agents and MCP demo

The agent/MCP demo: an npm workspace that uses the TypeScript SDK
([poc-sdks/typescript](../../poc-sdks/typescript/README.md)). The idea it follows is
"AI agents and MCP" in the root README's
[Where this could go](../../README.md#6-where-this-could-go).

| Folder | What it holds |
|---|---|
| [mock-github-mcp](mock-github-mcp/README.md) | mock GitHub MCP server (+ docs server), stdio, demo agent target |
| [pi-extension](pi-extension/README.md) | pi extension: stamps MCP calls, verifies responses, tracks influence |
| [eval](eval/README.md) | runs the agent many times per setting, scores from the outcome log, verify |
| [demo-ui](demo-ui/README.md) | local web page: one run at a time, evidence per call, results folders |
| `scenarios/` | scenario folders: repositories, planted text, scoring data |
| `policies/` | the client and server route policies that `setup-demo` signs |
| `scripts/` | `setup-demo`: throwaway demo keys and policies in `.demo/` (git-ignored) |

## Running it

The demo needs Node 22.19+ and Ollama. `./run agents-mcp` from the repository root
installs everything, sets up the demo keys and starts the page. By hand, install
the SDK first, because the packages here link it with `file:` paths:

```bash
(cd ../../poc-sdks/typescript && npm ci)
npm ci
npm run setup-demo
npm test
```

`npm run demo` opens a local page for one run ([demo-ui](demo-ui/README.md)).
`npm run eval -- --model ollama/<model>` repeats the runs and writes a results table ([eval](eval/README.md)).

## Protocol v3

The SDK and this demo speak protocol v3 ([spec](../../poc-sdks/spec/README.md)):

- **Every stamp names its receiver.** The run's origin names `pi`, a call names `mcp:<server>.<tool>`, a
  response chain ends at `pi`, the client that made the call, and a local step names `local:<tool>`. A chain
  sent anywhere else is refused `BINDING_MISMATCH`.
- **Objects as tokens.** A call's chain, proof and influence, the attestation or verdict on its result, and the
  handshake's request and reply each travel as a token, the base64url of the object's JCS bytes, and the SDK reads
  each from those bytes, never through the MCP transport's JSON parser. The evidence file keeps each token as sent
  or received, so `npm run verify` reads the bytes the live check read.
- **No transport peer here.** The SDK's verifier checks the sender a transport authenticated, and names it in
  every result. The MCP servers here run over stdio, which has no TLS, so there is no peer, and the peer check
  doesn't apply: attribution falls back to the chain's own rule.
- **Signed keyrings, pinned both ways.** `keyring.json` carries `sig`, the policy key's signature over it, and
  the extension sends it in the session request. The mock server pins the client policy key
  (`.demo/server/client-policy.pub`) and opens attested sessions only for it, as the extension pins the
  server's (`.demo/client/server-policy.pub`).

**Remaking `.demo`.** `./run agents-mcp` sets up the demo keys when `.demo` does not exist, and the demo checks
`.demo` each time it starts: it remakes the keys when a file is missing, does not read, or has a keyring, root or the
reply certificate within a day of expiring. The server and the extension refuse to start when a file there is missing
or does not read, when the keyring has no `sig` or `client-policy.pub` is missing, or when a keyring, root or the
reply certificate has expired. A server or extension started by hand is not checked that way; make the keys again
with:

```bash
npm run setup-demo -- --force
```
