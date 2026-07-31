# Examples

Runnable apps proving the gems against real frameworks and a real Keycard zone.
Each example carries its own Gemfile and consumes the gems via `path:` sources.

Planned (see ruby-sdk-plan.md):

- `mcp-server/`: an MCP server built on the official `mcp` gem, protected by
  `keycardai-mcp` bearer middleware and metadata endpoints. Lands with phase 2;
  verified with MCP Inspector plus a smoke script mirroring the templates
  repo's `ci-verify.sh` contract.
- `a2a-delegation/`: two local agents demonstrating discover, exchange, invoke
  with identity flow-through. Lands with phase 3.
