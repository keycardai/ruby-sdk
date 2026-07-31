# keycardai-a2a

Agent-to-agent delegation for Ruby agents on the Keycard platform.

> **Private preview.** Not published to rubygems.org.

Implements the delegation contract from
[keycard-sdk-spec](https://github.com/keycardai/keycard-sdk-spec)
(`specs/a2a/a2a-delegation.md`):

1. **Discover**: fetch and cache the target agent's card from
   `/.well-known/agent-card.json`
2. **Exchange**: RFC 8693 token exchange, subject = the inbound user token,
   authenticated by the calling agent's credential; the user stays the subject
   and the authorization server appends the caller to the `act` chain
3. **Invoke**: JSON-RPC `message/send` against the target with the exchanged
   token as the bearer credential

Hosting an agent inside a specific agent framework is out of scope, matching
the Go SDK's boundary. This gem wraps no A2A SDK.
