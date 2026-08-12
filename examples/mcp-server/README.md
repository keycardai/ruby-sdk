# mcp-server example

An MCP server built on the official [`mcp` gem](https://github.com/modelcontextprotocol/ruby-sdk),
protected by `keycardai-mcp`: bearer verification, OAuth discovery metadata,
and a scope-gated `/mcp` endpoint with one `hello` tool. This is the
compatibility proof for the SDK's no-MCP-dependency design: the integration
is plain Rack, and the official gem mounts behind it untouched.

## Run

```sh
bundle install
KEYCARD_URL=https://<your-zone>.keycard.cloud bundle exec rackup -p 8000
```

| Env var | Meaning |
| --- | --- |
| `KEYCARD_URL` | The zone issuer URL (required) |
| `KEYCARD_RESOURCE_ID` | Resource name advertised in metadata (default `mcp-server-ruby`) |

Endpoints: `GET /healthz`, `GET /.well-known/oauth-protected-resource`,
`GET /.well-known/oauth-authorization-server` (proxied from the zone),
`POST /mcp` (bearer-protected, scope `mcp:tools`).

## Verify

- `bin/smoke`: boots the server and checks the HTTP contract the Keycard
  templates repo verifies (healthz, both well-knowns, the 401 challenge).
  Needs a reachable `KEYCARD_URL`.
- `bin/selftest`: hermetic end-to-end proof with no live zone: stands up a
  stub zone (real RSA key, discovery + JWKS), boots this server against it,
  and drives the full flow including a signed token calling the `hello` tool,
  a 401 challenge, and a 403 insufficient_scope rejection.
- `bin/live-e2e`: runs the Integration Tests rows from keycard-sdk-spec
  against a real zone. Every block is guarded, so a partial config runs what
  it can and reports the rest as SKIP with the reason. Reads `KEYCARD_URL`,
  `KEYCARD_CLIENT_ID`, `KEYCARD_CLIENT_SECRET`, `KEYCARD_RESOURCE_ID`, and
  `KEYCARD_IMPERSONATE_USER` from the environment or a gitignored `.env` here.
  Impersonation mints a real zone token headlessly, so no browser login is
  needed to exercise the inbound verification and middleware rows.
