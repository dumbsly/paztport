# TypeScript SDK

An npm workspace of four packages. Node 22.19 or newer runs the `.ts` sources
directly, with no build step. Nothing is published: the agents demo
([poc-demos/agents-mcp](../../poc-demos/agents-mcp/README.md)) links the packages
with `file:` paths, and they resolve their own dependencies from this workspace,
so install it first.

```bash
npm install
npm test
```

## @paztport/core

The protocol, with no transport: base64url, Ed25519 and SHA-256 helpers,
canonical JSON, v1 and v2 stamps and chains, the salted Merkle tree, signed roots
and policy building, reason codes, the replay cache, prompt binding, influence and
the influence rule, sessions, local tool rules and the verdict for a local tool
call, local steps, and the live v1 and v2 chain verifiers. Offline verification of
a recorded run (`verifyChainOffline`) is here too, and shares its checks with the
live verifier; the agents demo's `npm run verify` uses it.

## @paztport/http

The v1 HTTP request binding (`bindHttp`): SHA-256 over method, path and body, as
the Java SDK computes it.

## @paztport/mcp

MCP transport on top of core: the `tools/call` binding, the `_meta` keys
(`paztport/chain`, `paztport/proof`, `paztport/influence` and the rest), the client
side (the session request and its reply, stamping a tool call, reading a tool
result's attestation) and the server side (`McpServerSession`, checking a call,
and the decision on a public write).

## policy-tool

`@paztport/policy-tool`: two command-line tools. `paztport-keygen` writes a
keypair per service, a policy keypair and a keyring; `paztport-policy` turns a
`paths.yaml` into a signed root and one proof bundle per service.
