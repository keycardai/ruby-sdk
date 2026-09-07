# keycardai-a2a

Agent-to-agent delegation for Ruby agents on the Keycard platform.

> Conformance against the cross-SDK contract is tracked in the
> [conformance report](https://github.com/keycardai/ruby-sdk/blob/main/docs/conformance-report.md).

```sh
bundle add keycardai-a2a
```

Implements the delegation contract from
[keycard-sdk-spec](https://github.com/keycardai/keycard-sdk-spec)
(`specs/a2a/a2a-delegation.md`):

1. **Discover**: fetch and cache the target agent's card from
   `/.well-known/agent-card.json`
2. **Exchange**: RFC 8693 token exchange, subject = the inbound user token,
   authenticated by the calling agent's credential; the user stays the subject
   and the authorization server appends the caller to the `act` chain
3. **Invoke**: JSON-RPC `SendMessage` (A2A protocol 1.0) against the target
   with the exchanged token as the bearer credential

Hosting an agent inside a specific agent framework is out of scope, matching
the Go SDK's boundary. This gem wraps no A2A SDK.

## Quickstart

### Call another agent on the user's behalf

```ruby
require "keycardai/a2a"

delegation = Keycardai::A2A::DelegationClient.new(
  issuer: ENV.fetch("KEYCARD_URL"),
  client_id: ENV.fetch("KEYCARD_CLIENT_ID"),
  client_secret: ENV.fetch("KEYCARD_CLIENT_SECRET"),
)

result = delegation.invoke(
  target: "https://agent-b.example.com",
  subject_token: inbound_user_token,
  message: Keycardai::A2A.text_message("summarize today's incidents"),
)

result.message      # the JSON-RPC result from agent B
result.agent_card   # the card that was discovered on the way
```

One call covers all three steps: fetch and cache agent B's card, exchange the
inbound token for one scoped to B, then send JSON-RPC `SendMessage` with the
exchanged token as the bearer credential. The user stays the subject across the
hop; agent B verifies a token whose `sub` is the original user, not this agent.

### Protocol version

The client speaks A2A protocol 1.0 by default: `SendMessage`, an `A2A-Version:
1.0` header, `ROLE_USER` roles, untagged text parts, and the invocation URL read
from the card's JSONRPC `supportedInterfaces` entry. Agents still on protocol
0.3 do not interoperate with the default; to reach one, pass
`protocol_version: Keycardai::A2A::LEGACY_PROTOCOL_VERSION`. That switches the
whole envelope generation (`message/send`, `X-A2A-Protocol-Version: 0.3`,
`user` roles, `kind`-tagged parts), so `Keycardai::A2A.text_message` output is
still the input either way. Any other value raises `ArgumentError`.

Failures are typed by stage, so you can tell "B is unreachable" from "the zone
refused the exchange":

```ruby
begin
  delegation.invoke(...)
rescue Keycardai::A2A::DiscoveryError => e     # no resolvable agent card
rescue Keycardai::OAuth::OAuthError => e       # the zone rejected the exchange
rescue Keycardai::A2A::InvocationError => e    # B was reached and failed
end
```

### Discover a card without invoking

```ruby
discovery = Keycardai::A2A::ServiceDiscovery.new
card = discovery.get_card("https://agent-b.example.com")
card["url"]
```

Cards are cached for 15 minutes by default (`cache_ttl:`). `refresh` forces a
fetch, `clear_cache` drops everything. Passing the same `ServiceDiscovery` into
`DelegationClient.new(discovery:)` shares one cache across both paths.
