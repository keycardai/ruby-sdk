# Security policy

Keycard sits in the credential path of every tool call an agent makes. A flaw in these gems is a flaw in someone's authorization boundary, so we treat reports here as high priority and we would rather hear about a maybe than miss a real one.

## Reporting a vulnerability

Do not open a public issue, pull request, or discussion for a security problem.

Use either channel:

- **GitHub private vulnerability reporting (preferred).** Go to the Security tab of this repository and open a private advisory. This keeps the report and our triage in one place.
- **Email security@keycard.ai.** If you want to encrypt, say so in a first message with no details and we will send you a key.

You do not need a working exploit to report something. A clear description of the flawed logic is enough.

Before you write it up, the platform's security model, token lifetimes, encryption scheme and threat model are documented in the [security architecture reference](https://docs.keycard.ai/reference/security-architecture/). It will tell you which behaviours are deliberate.

## What to include

The more of this you have, the faster we can act:

- Which gem and version (including keycardai-oauth, keycardai-mcp, and keycardai-a2a)
- Ruby version, the Rack version, and the application server in use (Puma, Falcon, Unicorn)
- What an attacker gains: which token, whose data, which scope they should not have had
- The smallest reproduction you can manage, ideally a failing spec
- Whether the issue needs a specific configuration or middleware order, and which

Please test against a zone you control. Do not probe other tenants' zones or use credentials that are not yours.

## What happens next

| Stage | Our commitment |
| --- | --- |
| Acknowledgement | Within 3 business days |
| Initial assessment and severity | Within 10 business days |
| Fix or documented mitigation | Target 30 days for high and critical severity |

If we conclude something is not a vulnerability we will explain the reasoning, and you are welcome to argue with it.

## Scope

### In scope for this repository

Anything that lets a caller obtain, keep, or use authority it should not have. Concretely:

- **Token validation.** Accepting an expired, unsigned, or wrong-algorithm token. Failing to check aud, iss, or the resource indicator. JWKS handling in Keycardai::OAuth that trusts the wrong key.
- **Token exchange (RFC 8693).** Scope escalation across an exchange, subject and actor confusion, a delegation chain that is dropped, forged, or not verifiable downstream. In Keycardai::A2A, an agent card that can steer a per-hop exchange somewhere it should not go.
- **Rack middleware bypass.** Any route reachable without the RFC 6750 bearer middleware having run, or with a token missing the required scope. Middleware that fails open on an internal error rather than returning 401. A middleware order that a reasonable reader would expect to be safe but is not.
- **Fail-open on a failed exchange.** Where the gems report an exchange failure rather than raising, middleware or handler code that carries on with a missing or failed grant is in scope, as is any case where the success path is reported for a grant that actually failed.
- **Metadata endpoints.** Anything in the RFC 9728 protected-resource or RFC 8414 authorization-server metadata handling that enables an authorization server mix-up.
- **Dynamic client registration (RFC 7591).** Registration reachable without authentication where it should not be, or weak redirect_uri validation on a registered client.
- **Credential exposure.** Client secrets, access tokens, or refresh tokens surfacing in logs, exception messages, inspect output, or a serialized Rack env. Framework error pages that dump env are a common way for a token in the wrong place to become a token in a bug tracker, so we treat that path as in scope.
- **Thread safety with a security consequence.** A token cache that can serve one request's credential to another under a threaded server is a critical finding, not a flake.
- **Insecure defaults.** A configuration that most users will reach for and that is weaker than it appears.
- PKCE, state, and nonce handling that permits replay, fixation, or cross-session confusion.

### Report to us, but not as a repository advisory

Issues in the hosted platform, the zone gateway, Keycard STS, Vault, or the Console, are not defects in this source tree. Email security@keycard.ai and say it concerns the hosted service. We will route it and keep you updated the same way.

### Out of scope

- Findings that presuppose an already-compromised host, root access, or a client secret the attacker somehow holds
- Documented design choices, unless you can show one is exploitable. Token lifetimes, refresh token reuse, and the fifteen minute data encryption key cache are described in the security architecture reference and were chosen deliberately
- Vulnerabilities in dependencies with no exploitable path through these gems. Report those upstream, and tell us so we can bump the constraint
- Missing security headers or TLS configuration on documentation sites, with no demonstrated impact
- Rate limiting or resource exhaustion without a concrete, realistic attack
- bundler-audit or scanner output with no analysis of exploitability
- Social engineering of Keycard staff, contributors, or customers

## Supported versions

These gems are pre-1.0 and maintain contract parity with the Python, TypeScript and Go SDKs. Treat a minor bump during 0.x.y as capable of containing breaking changes, as the sibling SDKs' policies state explicitly.

Security fixes land on the latest published minor release of each gem. We do not backport to earlier 0.x minors. If you are pinned to an older minor and cannot move, say so in your report and we will discuss options with you.

Ruby 3.2 and later are supported.

## Coordinated disclosure

We do not currently run a paid bug bounty.

**Safe harbour.** If you make a good-faith effort to follow this policy, we will not pursue or support legal action against you. Good faith means you do not access, modify, or exfiltrate data belonging to anyone else, you do not degrade the service for other users, you stop at the point where you have demonstrated the problem, and you give us a reasonable chance to fix it before going public.

## Regulatory reporting

Keycard Labs, Inc. may be obliged under Article 14 of Regulation (EU) 2024/2847, the EU Cyber Resilience Act, to notify ENISA and a national CSIRT within 24 hours of becoming aware that a vulnerability in one of our products is being actively exploited.

Those notifications describe the vulnerability and the affected products. They do not include your identity or contact details unless you ask us to name you. If a report you send us triggers this obligation, we will tell you that it did.

## Contact

- Security reports: security@keycard.ai
- Everything else: support@keycard.ai
