# Paztport demos

The demos only wire the SDKs ([poc-sdks](../poc-sdks/README.md)) together: the
services, transport plumbing, UI, fixtures and harnesses around them. Each builds
on its own and has its own README.

- [java-mesh](java-mesh/README.md): a mesh of Spring Boot services on the Java SDK,
  with a responder that quarantines offending containers. `./run java-mesh` from
  the repository root builds and runs it (needs Docker).
- [agents-mcp](agents-mcp/README.md): an agent and its MCP servers on the
  TypeScript SDK, with the evaluation and a local demo page. `./run agents-mcp`
  from the repository root sets it up and starts the page.
