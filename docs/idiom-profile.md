# Ruby idiom profile

How the canonical keycard-sdk-spec contract maps onto Ruby. This is the Ruby
column of PHILOSOPHY.md's idiom profile; it moves to `context/ruby.md` in
keycard-sdk-spec when this SDK is revealed. A cross-SDK expression difference
is acceptable only if it is sanctioned here; anything else is a contract bug.

| Category | Ruby transform |
| --- | --- |
| Naming case | `snake_case` methods, `PascalCase` classes/modules. Spec identifiers map directly (`verify_token_for_zone`). |
| Namespace | Top module `Keycardai`. Gems map dash-to-nesting: `keycardai-oauth` is `Keycardai::OAuth`, `keycardai-mcp` is `Keycardai::MCP`, `keycardai-a2a` is `Keycardai::A2A`. |
| Async model | Sync-only, blocking, like Go. Python's `Client`/`AsyncClient` pair collapses to one `Client`. Internals are thread-safe (Mutex-guarded JWKS and discovery caches) because Puma and Sidekiq are threaded. |
| Calling convention | Keyword arguments, the analog of Python kwargs and TS options objects. No functional-options pattern. |
| Errors | Exceptions rooted at `Keycardai::Error`. The spec's error categories map to subclasses; discriminator codes ride as attributes (`error`, `error_description`). |
| Host-framework shape | Rack: middleware for enforcement (`use provider.grant(...)`), Rack apps for metadata endpoints. Handlers read verified identity and exchanged tokens from the Rack env (`keycardai.auth_info`, `keycardai.access_context`). |
| Operation shape | Flat methods on client objects, matching Python/TS. |
| Native values | Keys as `OpenSSL::PKey`, times as `Time`, JSON payloads as hashes with symbol keys at the public surface. |
| HTTP pluggability | A small internal HTTP-client interface with a `Net::HTTP` default, injectable per client (`http_client:` kwarg). No hidden retries, per base.md. |
| JWT/JWKS | The `jwt` gem (ruby-jwt) and its JWK support. |

## Decisions ratified (2026-07-31)

1. **Tests**: RSpec. The conformance suite mirrors keycard-sdk-spec: each
   capability spec's Testing tables live in
   `spec/conformance/<spec-slug>_spec.rb`.
2. **Verifier construction**: one `TokenVerifier` class with a zone argument
   (`verify_token_for_zone`), the TS/Python shape, not Go's three constructors.
3. **Environment variables**: no implicit reads of Keycard configuration,
   matching TS/Go and the spec family (base.md, restated by the rewritten
   client-secret / web-identity / workload-identity specs). The single blessed
   exception is `FileTokenSource` path discovery via the platform-convention
   vars (`KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE`,
   `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
   `AZURE_FEDERATED_TOKEN_FILE`, in that order; explicit `token_file_path:`
   wins, `env_var_name:` prepends). Credential discovery for the `keycard run`
   flow ships as an explicit opt-in helper
   (`discover_application_credential(env: ENV)`), never a constructor fallback.
   Python's `AuthProvider` env fallbacks are the outlier and are deliberately
   not mirrored.
4. **Namespace spelling**: `Keycardai` (matches the `keycardai` brand string in
   every package ecosystem).
5. **Ruby floor**: `>= 3.2`. Dev version pinned by `.ruby-version`.
6. **Lint**: RuboCop, config at the repo root.
7. **Versioning**: per-gem, commitizen-style tags
   (`<version>-keycardai-<gem>`), wired up at public launch, not before.
   Commit scopes always use the full gem name (`feat(keycardai-oauth):`).
8. **MCP shape**: wraps no MCP SDK (Go's model). Attach at the Rack seam;
   prove compatibility with the official `mcp` gem via `examples/`.
9. **A2A shape**: delegation client only (Go's boundary); no dependency on
   community A2A gems.
