# a2a-delegation example

Two agents demonstrating the A2A delegation contract from
[keycard-sdk-spec](https://github.com/keycardai/keycard-sdk-spec)
(`specs/a2a/a2a-delegation.md`): one agent calls another **on the user's
behalf**, and the user's identity survives the hop.

- **`agent_b.ru`**, the downstream agent. Publishes its agent card at
  `/.well-known/agent-card.json` and a JSON-RPC endpoint at `/a2a/jsonrpc`
  protected by `keycardai-mcp` bearer verification. It reports the subject it
  verified, which is the proof of flow-through: B checks the token against the
  zone's JWKS itself rather than trusting anything the caller says. Its
  verifier is audience-bound to its own URL, so a token minted for another
  audience is refused even though the same zone signed it.
- **`agent_a.ru`**, the calling agent. On `POST /delegate` it discovers B's
  card, exchanges the inbound user token for one scoped to B (RFC 8693, the
  user stays the subject), and invokes B.

## Run the agents

```sh
bundle install
KEYCARD_URL=https://<zone>.keycard.cloud bundle exec rackup -q agent_b.ru -p 9601 &
KEYCARD_URL=https://<zone>.keycard.cloud KEYCARD_CLIENT_ID=... KEYCARD_CLIENT_SECRET=... \
  bundle exec rackup -q agent_a.ru -p 9602 &
curl -X POST localhost:9602/delegate -H "authorization: Bearer <user-token>" \
  -H 'content-type: application/json' -d '{"text":"hello"}'
```

## Verify

- **`bin/selftest`**: hermetic and needs no zone. Stands up a stub zone whose
  token endpoint performs a real RFC 8693 exchange (verifying client auth,
  preserving the subject, re-scoping the audience, recording the caller in
  `act`), boots both agents, and asserts the whole chain: card discovery, the
  401 challenge on an unauthenticated call, the exchange carrying the user
  token as subject under the token-exchange grant, B verifying `sub` as the
  original user, the re-scoped audience, the `act` entry, and rejection of a
  token minted for a different audience.
- **`bin/live`**: the same two agents against a real zone. Registers agent B
  as a zone resource on first run, then proves B verifies a genuine
  zone-issued token for the user.

  ```sh
  keycard auth signin --org <org-id> --zone <zone-id>
  ZONE=<zone-id> ORG=<org-id> bin/live
  ```

  Credentials come from `../mcp-server/.env`, so run
  `../mcp-server/bin/provision` first.

## Two token paths, and why

Agent A prefers an inbound `Authorization` bearer token and exchanges it,
which is the real delegation path and what `bin/selftest` proves end to end.
With no inbound user it falls back to impersonating a configured user directly
for B, which is what `bin/live` exercises. Either way the exchange leg needs
the calling client to own the resource named in the subject token's `aud`:
`svc-sts` gates re-exchange on `resource.application_id`, so a zone whose
resources have no owner refuses every exchange with `invalid_grant` while
impersonation keeps working. `bin/provision` sets that field.

One known gap, tracked upstream and owned by another team: the spec expects
the authorization server to record the calling agent in the issued token's
`act` chain when the exchange is authenticated by the agent's own credential.
`svc-sts` populates actor information only from an explicit `actor_token`, so
a live zone returns no `act` claim for this flow. The stub zone in
`bin/selftest` emits `act` because that is what the contract calls for, which
is why the hermetic run asserts it and the live run only reports it.
