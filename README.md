# Keycard Ruby SDK

> **Preview.** APIs may change between minor versions while the surface settles.
> The parity contract these gems implement lives in
> [keycard-sdk-spec](https://github.com/keycardai/keycard-sdk-spec), and where
> this SDK stands against it is in
> [docs/conformance-report.md](docs/conformance-report.md).

Ruby SDK for the Keycard agentic identity platform, at contract parity with the
[Python](https://github.com/keycardai/python-sdk),
[TypeScript](https://github.com/keycardai/typescript-sdk), and
[Go](https://github.com/keycardai/go-sdk) SDKs.

## Gems

| Gem | Namespace | Purpose |
| --- | --- | --- |
| `keycardai-oauth` | `Keycardai::OAuth` | OAuth 2.0 primitives: token exchange (RFC 8693), client credentials, authorization code + PKCE, DCR (RFC 7591), discovery (RFC 8414), JWT/JWKS verification, application credentials, AccessContext |
| `keycardai-mcp` | `Keycardai::MCP` | MCP server integration: Rack bearer middleware (RFC 6750), OAuth metadata endpoints (RFC 9728/8414), AuthProvider with delegated token exchange |
| `keycardai-a2a` | `Keycardai::A2A` | Agent-to-agent delegation: agent card discovery, per-hop token exchange, JSON-RPC invocation |

`keycardai-oauth` is the foundation; the other two depend on it and stay slim.
The MCP gem wraps no MCP SDK: it attaches at the Rack seam, and compatibility
with the official [`mcp` gem](https://github.com/modelcontextprotocol/ruby-sdk)
is proven by the example server in `examples/`.

## Install

```sh
bundle add keycardai-oauth      # OAuth primitives on their own
bundle add keycardai-mcp        # protecting an MCP server; pulls in oauth
bundle add keycardai-a2a        # agent-to-agent delegation; pulls in oauth
```

Or with `gem install keycardai-oauth`. Each gem's own README has a copy-paste
quickstart: [oauth](oauth/README.md), [mcp](mcp/README.md), [a2a](a2a/README.md).

## Development

Requires Ruby >= 3.2 (`.ruby-version` pins the dev version).

```sh
bundle install
bundle exec rake          # specs + rubocop
bundle exec rake spec     # specs only
bundle exec rake rubocop  # lint only
```

Specs are organized as the conformance suite: each capability spec in
keycard-sdk-spec maps to a `spec/conformance/<spec-slug>_spec.rb` implementing
its Testing tables.

Design decisions and the Ruby idiom profile are in
[docs/idiom-profile.md](docs/idiom-profile.md). Where this SDK stands against
the spec, including live-zone results and findings raised upstream, is in
[docs/conformance-report.md](docs/conformance-report.md).

## Commits and releases

Conventional commits with the **full gem name** as scope, matching the sibling
SDKs: `feat(keycardai-oauth): ...`, not `feat(oauth): ...`. That scope is what
decides which gem releases, so a short scope silently produces no release.
Squash merges mean the PR title is what carries it.

How a change becomes a published gem, what the repo settings and trusted
publishers have to be, and what to do when a release goes sideways are in
[docs/releasing.md](docs/releasing.md).
