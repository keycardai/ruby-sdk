# keycardai-mcp

Keycard integration for MCP servers in Ruby, attached at the Rack seam.

> **Private preview.** Not published to rubygems.org.

What it ships (per [keycard-sdk-spec](https://github.com/keycardai/keycard-sdk-spec)):

- Bearer-token verification middleware: fail-closed 401 with an RFC 6750
  `WWW-Authenticate` challenge advertising `resource_metadata`
- OAuth metadata endpoints: RFC 9728 protected-resource metadata with path
  insertion, RFC 8414 authorization-server metadata proxy, `/.well-known/jwks.json`
- AuthProvider: `grant(resources)` middleware for delegated token exchange
  (RFC 8693) plus imperative `exchange_tokens`
- Rack env accessors for the verified `AuthInfo` and the `AccessContext`

This gem wraps no MCP SDK. It works with any Rack app; compatibility with
servers built on the official [`mcp` gem](https://github.com/modelcontextprotocol/ruby-sdk)
is proven by the example server in the repo's `examples/` directory.
