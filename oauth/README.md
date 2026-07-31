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
