# Paztport demos

The demos only wire the SDKs ([poc-sdks](../poc-sdks/README.md)) together: the
services, transport plumbing, UI, fixtures and harnesses around them. Each builds
on its own and has its own README.

- [java-mesh](java-mesh/README.md): a mesh of Spring Boot services on the Java SDK,
  with a responder that quarantines offending containers, and a support-assistant
  storyline across two organisations. `./run java-mesh` from
  the repository root builds and runs it (needs Docker).
- [envoy-gateway](envoy-gateway/README.md): Paztport at an Envoy Gateway edge, a Go
  `ext_proc` processor that stamps each request as the origin `edge`, its Helm chart,
  and checks on a local kind cluster against java-mesh's `orders` and `payment`.
  `./run envoy-gateway` from the repository root builds it, brings it up and runs
  the checks (needs Maven on Java 25, Docker, Go, kind, kubectl and Helm).
- [agents-mcp](agents-mcp/README.md): an agent and its MCP servers on the
  TypeScript SDK, with the evaluation and a local demo page. `./run agents-mcp`
  from the repository root sets it up and starts the page.
