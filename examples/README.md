# Examples

Runnable apps proving the gems against real frameworks and a real Keycard
zone. Each example carries its own Gemfile and consumes the gems via `path:`
sources.

- [`mcp-server/`](mcp-server/): an MCP server built on the official `mcp` gem,
  protected by `keycardai-mcp` bearer middleware and metadata endpoints.
  `bin/provision` stands up the zone objects via the Management API,
  `bin/selftest` is a hermetic end-to-end run against a stub zone,
  `bin/live-e2e` executes the spec's Integration Tests rows against a real
  zone, and `bin/smoke` checks the templates-repo HTTP contract.
- [`a2a-delegation/`](a2a-delegation/): two agents demonstrating the A2A
  delegation contract, where one calls the other on the user's behalf and the
  user's identity survives the hop. `bin/selftest` proves the full
  discover/exchange/invoke chain hermetically, including audience binding;
  `bin/live` runs the same agents against a real zone.
