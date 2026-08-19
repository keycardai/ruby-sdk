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

## Quickstart

### Protect an endpoint

```ruby
require "keycardai/mcp"

zone_url = ENV.fetch("KEYCARD_URL")

verifier = Keycardai::OAuth::TokenVerifier.new(issuers: zone_url)
metadata = Keycardai::MCP::MetadataApp.new(
  issuer: zone_url,
  resource_name: "mcp-server-ruby",
  scopes_supported: ["mcp:tools"],
)

protected_mcp = Keycardai::MCP::RequireBearerAuth.new(
  your_mcp_endpoint, verifier: verifier, required_scopes: ["mcp:tools"],
)

run lambda { |env|
  case env["PATH_INFO"]
  when %r{\A/\.well-known/} then metadata.call(env)
  when "/mcp" then protected_mcp.call(env)
  else [404, { "content-type" => "application/json" }, ['{"error":"not_found"}']]
  end
}
```

An unauthenticated request gets a 401 with an RFC 6750 `WWW-Authenticate`
challenge pointing at `resource_metadata`, which is what lets a client discover
where to authenticate. `MetadataApp` serves the RFC 9728 protected-resource
document, proxies the zone's RFC 8414 authorization-server metadata, and serves
`/.well-known/jwks.json`.

Inside the handler, the verified token is on the Rack env:

```ruby
auth = Keycardai::MCP.auth_info(env)
auth.subject
auth.scopes
```

### Get tokens for downstream resources

```ruby
provider = Keycardai::MCP::AuthProvider.new(
  zone_url: zone_url,
  client_id: ENV.fetch("KEYCARD_CLIENT_ID"),
  client_secret: ENV.fetch("KEYCARD_CLIENT_SECRET"),
)

use provider.grant(["https://api.github.com", "https://slack.com/api"])
```

By the time the handler runs, the caller's token has been exchanged once per
resource and the results are on the env:

```ruby
context = Keycardai::MCP.access_context(env)
context.access("https://api.github.com")  # raises if that resource failed
context.status                            # "success", "partial_error", or "error"
```

A single resource failing does not abort the request; it lands on the context.
A missing verified token does abort, 401, before any exchange is attempted.
Stacked `grant` calls merge into one context.

To act as a named user instead of the caller, pass `user_identifier:` (a string,
or a callable that receives the Rack env). For an imperative call outside the
middleware, `provider.exchange_tokens(token, resources)` returns the same
`AccessContext`.
