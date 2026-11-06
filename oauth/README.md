# keycardai-oauth

OAuth 2.0 primitives for the Keycard platform. The foundation gem of the
[Keycard Ruby SDK](https://github.com/keycardai/ruby-sdk); `keycardai-mcp` and
`keycardai-a2a` build on it.

> Conformance against the cross-SDK contract is tracked in the
> [conformance report](https://github.com/keycardai/ruby-sdk/blob/main/docs/conformance-report.md).

```sh
bundle add keycardai-oauth
```

Capabilities:

- Token exchange and impersonation (RFC 8693)
- Client credentials grant (RFC 6749 §4.4)
- Authorization code + PKCE, including the challenge-driven loopback flow (RFC 8252)
- Device authorization grant (RFC 8628)
- Dynamic client registration (RFC 7591)
- Authorization server discovery (RFC 8414), including the OIDC Discovery 1.0 §3 endpoints
- UserInfo: the signed-in user's identity claims (OIDC Core 1.0 §5.3)
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

### Read the signed-in user's claims

```ruby
user = Keycardai::OAuth.fetch_userinfo(
  "https://your-zone.keycard.cloud",
  access_token: user_access_token,
)

user.sub
user["email"]
user["groups"]
```

Zone access tokens are authorization-only, so identity claims live behind the
issuer's `userinfo_endpoint` rather than in the token. Pass `metadata:` to reuse
metadata you already discovered; nothing is cached, because group membership can
change server-side.

### Refresh a stored grant

A token response from the authorization-code flow may carry a `refresh_token`.
Redeem it with `refresh_authorization`, which authenticates the client the way
`exchange_authorization_code` does. The gem keeps no state: when the response
carries a new `refresh_token`, the server rotated it and you store it in place
of the old one. `OAuthError` with `error == "invalid_grant"` means the user must
authorize again.

```ruby
token = Keycardai::OAuth.refresh_authorization(
  "https://your-zone.keycard.cloud",
  refresh_token: stored_refresh_token,
  client_id: ENV.fetch("KEYCARD_CLIENT_ID"),
  client_secret: ENV["KEYCARD_CLIENT_SECRET"], # omit for a public client
  resources: ["https://api.acme.test"],
)
stored_refresh_token = token.refresh_token if token.refresh_token
```

A client with a credential passes `credential:` in place of `client_id` and
`client_secret`. The credential must respond to `client_authentication`.

### Sign in a device with no browser

The device authorization grant (RFC 8628) lets a process with no browser get a
token for a person. Show the person the verification URI and the user code,
then wait while they confirm on another device.

```ruby
device = Keycardai::OAuth::DeviceAuthorizationClient.new(
  issuer: "https://your-zone.keycard.cloud",
  credential: credential, # or client_id: "..." for a public client
)

authorization = device.request_device_authorization(scopes: ["openid"])
puts "Visit #{authorization.verification_uri_complete || authorization.verification_uri}"
puts "and confirm the code #{authorization.user_code}"

begin
  token = device.wait_for_token(authorization, deadline: Time.now + 300)
rescue Keycardai::OAuth::DevicePollError => e
  # A network error, a 5xx, or a 429 stopped the loop. e.cause is the failure.
  # Resume later with: device.wait_for_token(authorization, interval: e.interval)
end
```

`wait_for_token` raises `OAuthError` with `error == "access_denied"` when the
person denies the request, and `"expired_token"` when the code expires first.
Pass `cancelled:` (a callable) or `deadline:` (a `Time`) to stop the wait.
A request already in flight runs to completion. A token from a request with
more than one resource is not for any one of them. To get a token for one
resource, refresh with `resources: [that_resource]`.

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
