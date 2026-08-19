# keycardai-oauth

OAuth 2.0 primitives for the Keycard platform. The foundation gem of the
[Keycard Ruby SDK](https://github.com/keycardai/ruby-sdk); `keycardai-mcp` and
`keycardai-a2a` build on it.

> **Private preview.** Not published to rubygems.org.

Capabilities (per [keycard-sdk-spec](https://github.com/keycardai/keycard-sdk-spec)):

- Token exchange and impersonation (RFC 8693)
- Client credentials grant (RFC 6749 §4.4)
- Authorization code + PKCE, including the challenge-driven loopback flow (RFC 8252)
- Dynamic client registration (RFC 7591)
- Authorization server discovery (RFC 8414)
- JWT signing and verification, JWKS keyring with caching
- Application credentials: ClientSecret (incl. multi-zone), WebIdentity (RFC 7523),
  WorkloadIdentity with pluggable identity token sources
- AccessContext: the non-throwing per-request container for delegated tokens

## Quickstart

### Verify an inbound token

```ruby
require "keycardai/oauth"

verifier = Keycardai::OAuth::TokenVerifier.new(
  issuers: "https://your-zone.keycard.cloud",
  audiences: "your-resource-id",
)

begin
  token = verifier.verify_token(bearer_token)
  puts token.subject
  puts token.scopes
rescue Keycardai::OAuth::InvalidTokenError => e
  # Fail closed: every verification failure is this one error type.
  warn "rejected: #{e.message}"
end
```

The verifier resolves signing keys through a JWKS keyring that caches per
`(issuer, kid)`, so a second verification of the same token does no network I/O.

### Exchange a caller's token for a downstream resource

```ruby
client = Keycardai::OAuth::TokenExchangeClient.new(
  issuer: "https://your-zone.keycard.cloud",
  client_id: ENV.fetch("KEYCARD_CLIENT_ID"),
  client_secret: ENV.fetch("KEYCARD_CLIENT_SECRET"),
)

result = client.exchange_token(
  subject_token: bearer_token,
  resource: "https://api.github.com",
  scope: "repo:read",
)
result.access_token
```

Nothing here reads the environment on your behalf. Configuration is read in
application code and passed in explicitly, which is the cross-SDK contract.

### Several resources at once

```ruby
context = Keycardai::OAuth.exchange_tokens_for_resources(
  client: client,
  subject_token: bearer_token,
  resources: ["https://api.github.com", "https://slack.com/api"],
)

context.status                        # "success", "partial_error", or "error"
context.access("https://api.github.com")  # raises if that one resource failed
context.failed_resources
```

One resource failing never takes down the others; the failure lands on the
context rather than raising, and `access` is where you choose to raise.

### Act as a named user

```ruby
result = client.impersonate(
  user_identifier: "user@example.com",
  resource: "https://api.github.com",
)
```

The issued token's `sub` is the target user. It is a leaf credential: a zone
refuses it as the subject of a further exchange, so impersonate again rather
than trying to trade it up.
