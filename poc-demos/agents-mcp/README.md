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
