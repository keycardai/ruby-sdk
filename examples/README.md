# Examples

Runnable apps proving the gems against real frameworks. Each example carries
its own Gemfile and consumes the gems via `path:` sources.

- [`mcp-server/`](mcp-server/): an MCP server built on the official `mcp` gem,
  protected by `keycardai-mcp` bearer middleware and metadata endpoints. Comes
  with `bin/smoke` (the templates-repo HTTP contract, needs a reachable zone)
  and `bin/selftest` (hermetic end-to-end proof with a stub zone and real
  signed tokens; no network).

Planned (see ruby-sdk-plan.md):

- `a2a-delegation/`: two local agents demonstrating discover, exchange, invoke
  with identity flow-through. Lands with the live-zone E2E phase.
