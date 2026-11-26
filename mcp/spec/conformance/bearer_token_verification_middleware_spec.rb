# frozen_string_literal: true

require "jwt"
require "openssl"

# Conformance suite for keycard-sdk-spec
# specs/server-bearer-auth/bearer-token-verification-middleware.md
# (spec-version 8). Each numbered example maps to a Unit Tests row;
# rows exercising construction, resource binding, and audience verification use
# a real TokenVerifier over in-memory zones.
RSpec.describe Keycardai::MCP::RequireBearerAuth do
  let(:probe) { ProbeApp.new }
  let(:verifier) { FakeVerifier.new("at_valid" => access_token) }

  def middleware(**options)
    described_class.new(probe, verifier: verifier, **options)
  end

  # Zones with RSA keys served through an in-memory transport.
  let(:zone_issuer) { "https://acme.test" }
  let(:base_issuer) { "https://keycard.cloud" }
  let(:zone_a_issuer) { "https://a.keycard.cloud" }
  let(:zone_b_issuer) { "https://b.keycard.cloud" }
  let(:zone_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:zone_a_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:zone_b_key) { OpenSSL::PKey::RSA.new(2048) }

  def jwks_for(key, kid)
    jwk = JWT::JWK.new(key.public_key, { kid: kid, use: "sig", alg: "RS256" })
    { "keys" => [jwk.export.transform_keys(&:to_s)] }
  end

  let(:zone_http) do
    keys_by_issuer = {
      zone_issuer => [zone_key, "kid-1"],
      zone_a_issuer => [zone_a_key, "kid-a"],
      zone_b_issuer => [zone_b_key, "kid-b"]
    }
    FakeHTTPClient.new do |url, _params|
      issuer = keys_by_issuer.keys.find { |iss| url.start_with?("#{iss}/") }
      next http_json({}, status: 404) unless issuer

      key, kid = keys_by_issuer[issuer]
      case url
      when "#{issuer}/.well-known/oauth-authorization-server"
        http_json({ "issuer" => issuer, "jwks_uri" => "#{issuer}/.well-known/jwks.json",
                    "token_endpoint" => "#{issuer}/oauth/token" })
      when "#{issuer}/.well-known/jwks.json"
        http_json(jwks_for(key, kid))
      else
        http_json({}, status: 404)
      end
    end
  end

  let(:foreign_resource_token) { token_with_audience("https://other.example.com") }

  def token_with_audience(audience, issuer: zone_issuer, key: zone_key, kid: "kid-1", scope: "mcp:tools")
    claims = { "iss" => issuer, "sub" => "usr_123", "aud" => audience,
               "exp" => Time.now.to_i + 300, "iat" => Time.now.to_i,
               "client_id" => "client_abc", "scope" => scope }
    JWT.encode(claims, key, "RS256", { "kid" => kid })
  end

  def real_verifier(issuers: zone_issuer, **options)
    Keycardai::OAuth::TokenVerifier.new(issuers: issuers, http_client: zone_http, **options)
  end

  it "1: a missing Authorization header yields 401 with a resource_metadata challenge" do
    gated = described_class.new(probe, verifier: real_verifier(resource_identifier: "https://tool.example.com/mcp"))

    status, headers, = gated.call(rack_env(path: "/mcp"))

    expect(status).to eq(401)
    expect(headers["www-authenticate"])
      .to eq('Bearer resource_metadata="https://tool.example.com/.well-known/oauth-protected-resource/mcp"')
    expect(probe.ran?).to be(false)
  end

  it "2: a header that is not two parts yields 400" do
    expect(middleware.call(rack_env(headers: { "Authorization" => "Bearer" })).first).to eq(400)
    expect(middleware.call(rack_env(headers: { "Authorization" => "Bearer a b" })).first).to eq(400)
  end

  it "3: a non-bearer scheme yields 401 invalid_token" do
    status, headers, = middleware.call(rack_env(headers: { "Authorization" => "Basic abc" }))

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include('error="invalid_token"')
  end

  it "4: a valid token proceeds with the auth context exposing the caller's identity, scopes, and expiry" do
    status, = middleware.call(rack_env(headers: { "Authorization" => "Bearer at_valid" }))

    expect(status).to eq(200)
    info = Keycardai::MCP.auth_info(probe.seen_env)
    expect(info.client_id).to eq("client_abc")
    expect(info.subject).to eq("usr_123")
    expect(info.subject_profile).to eq("user")
    expect(info.keycard_app_id).to eq("app_abc")
    expect(info.scopes).to eq(["mcp:tools"])
    expect(info.expires_at).to be > Time.now
    expect(info.audiences).to eq(["https://tool.example.com"])
  end

  it "4a: an application token reports subject_profile app, with subject equal to keycard_app_id" do
    app_token = access_token(token: "at_app", sub: "app_abc", sub_profile: "app", keycard_app_id: "app_abc")
    gated = described_class.new(probe, verifier: FakeVerifier.new("at_app" => app_token))

    gated.call(rack_env(headers: { "Authorization" => "Bearer at_app" }))

    info = Keycardai::MCP.auth_info(probe.seen_env)
    expect(info.subject_profile).to eq("app")
    expect(info.subject).to eq(info.keycard_app_id)
  end

  it "4b: the Keycard claims are optional, so a non-Keycard token reports them as nil" do
    plain = access_token(token: "at_plain", sub_profile: nil, keycard_app_id: nil)
    gated = described_class.new(probe, verifier: FakeVerifier.new("at_plain" => plain))

    gated.call(rack_env(headers: { "Authorization" => "Bearer at_plain" }))

    info = Keycardai::MCP.auth_info(probe.seen_env)
    expect(info.subject_profile).to be_nil
    expect(info.keycard_app_id).to be_nil
    expect(info.client_id).to eq("client_abc")
  end

  context "with the verified audience and actor claims" do
    let(:gated) do
      described_class.new(probe, verifier: real_verifier(multi_resource: true, audiences: ["resource-a"]))
    end

    def signed_caller_token(aud, **extras)
      now = Time.now.to_i
      claims = { "iss" => zone_issuer, "sub" => "usr_123", "client_id" => "client_abc",
                 "iat" => now, "exp" => now + 300, "aud" => aud }.merge(extras.transform_keys(&:to_s))
      JWT.encode(claims, zone_key, "RS256", { "kid" => "kid-1" })
    end

    it "4a: exposes all audiences and the complete actor chain" do
      actor = { "sub" => "actor", "act" => { "sub" => "previous" } }
      token = signed_caller_token(%w[resource-a resource-b], act: actor)

      status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{token}" }))

      expect(status).to eq(200)
      claims = Keycardai::MCP.auth_info(probe.seen_env).claims
      expect(claims["aud"]).to eq(%w[resource-a resource-b])
      expect(claims["act"]).to eq(actor)
    end

    it "4b: exposes a string audience as a one-element array" do
      token = signed_caller_token("resource-a")

      status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{token}" }))

      expect(status).to eq(200)
      expect(Keycardai::MCP.auth_info(probe.seen_env).claims["aud"]).to eq(["resource-a"])
    end
  end

  it "5: an invalid token yields 401 invalid_token" do
    status, headers, = middleware.call(rack_env(headers: { "Authorization" => "Bearer at_bogus" }))

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include('error="invalid_token"', "resource_metadata=")
    expect(probe.ran?).to be(false)
  end

  it "6: a valid token missing a required scope yields 403 insufficient_scope" do
    gated = middleware(required_scopes: %w[mcp:tools admin])

    status, headers, = gated.call(rack_env(headers: { "Authorization" => "Bearer at_valid" }))

    expect(status).to eq(403)
    expect(headers["www-authenticate"]).to include('error="insufficient_scope"', "resource_metadata=")
    expect(probe.ran?).to be(false)
  end

  it "7: constructing without an identifier or audience mode warns once naming resource_identifier " \
     "and retains legacy audience acceptance" do
    unbound = nil
    expect { unbound = real_verifier }
      .to output(/warning: .*resource_identifier/).to_stderr
    gated = described_class.new(probe, verifier: unbound)

    status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{foreign_resource_token}" }))

    expect(status).to eq(200)
    expect(Keycardai::MCP.auth_info(probe.seen_env).audiences).to eq(["https://other.example.com"])
  end

  it "8: resource_identifier emits no warning and rejects a same-zone token for another resource" do
    bound = nil
    expect { bound = real_verifier(resource_identifier: "https://api.example.com/mcp") }.not_to output.to_stderr
    gated = described_class.new(probe, verifier: bound)
    other = token_with_audience("https://api.example.com/other")

    status, headers, = gated.call(rack_env(path: "/mcp", headers: { "Authorization" => "Bearer #{other}" }))

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include('error="invalid_token"')
    expect(probe.ran?).to be(false)
  end

  [
    ["8a: multi_resource with audiences accepts a scalar audience matching the second value", "resource-b", 200],
    ["8b: multi_resource with audiences rejects a scalar audience without a match", "resource-c", 401],
    ["8c: multi_resource with audiences accepts an array audience with one match", %w[resource-c resource-b], 200],
    ["8d: multi_resource with audiences rejects an array audience without a match", %w[resource-c resource-d], 401]
  ].each do |description, audience, expected_status|
    it description do
      bound = nil
      expect do
        bound = real_verifier(multi_resource: true, audiences: %w[resource-a resource-b])
      end.not_to output.to_stderr
      gated = described_class.new(probe, verifier: bound)
      token = token_with_audience(audience)
      status, headers, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{token}" }))

      expect(status).to eq(expected_status)
      expect(headers["www-authenticate"]).to include('error="invalid_token"') if expected_status == 401
    end
  end

  it "8e: multi_resource with an explicitly empty audiences list raises at construction without warning" do
    expect do
      expect { real_verifier(multi_resource: true, audiences: []) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /audiences/)
    end.not_to output.to_stderr

    expect do
      expect { Keycardai::MCP::AuthProvider.new(zone_url: zone_issuer, multi_resource: true, audiences: []) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /audiences/)
    end.not_to output.to_stderr
  end

  it "8f: multi_resource with audiences omits resource_metadata on 401 and emits no warning" do
    bound = nil
    expect do
      bound = real_verifier(multi_resource: true, audiences: %w[resource-a resource-b])
    end.not_to output.to_stderr
    gated = described_class.new(probe, verifier: bound)

    ok_status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{token_with_audience("resource-b")}" }))
    bad_status, bad_headers, = gated.call(
      rack_env(headers: { "Authorization" => "Bearer #{token_with_audience("resource-c")}" })
    )

    expect(ok_status).to eq(200)
    expect(bad_status).to eq(401)
    expect(bad_headers["www-authenticate"]).to include('error="invalid_token"')
    expect(bad_headers["www-authenticate"]).not_to include("resource_metadata=")
  end

  it "8g: allow_any_audience accepts another resource, rejects invalid signature without resource_metadata" do
    bound = nil
    expect { bound = real_verifier(allow_any_audience: true) }.not_to output.to_stderr
    gated = described_class.new(probe, verifier: bound)

    ok_status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{foreign_resource_token}" }))
    forged = token_with_audience("https://other.example.com", key: OpenSSL::PKey::RSA.new(2048))
    bad_status, bad_headers, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{forged}" }))

    expect(ok_status).to eq(200)
    expect(bad_status).to eq(401)
    expect(bad_headers["www-authenticate"]).to include('error="invalid_token"')
    expect(bad_headers["www-authenticate"]).not_to include("resource_metadata=")
  end

  it "8h: URN resource_identifier enforces exact aud match and omits resource_metadata" do
    bound = nil
    expect { bound = real_verifier(resource_identifier: "urn:example:service") }.not_to output.to_stderr
    gated = described_class.new(probe, verifier: bound)

    ok_status, = gated.call(
      rack_env(headers: { "Authorization" => "Bearer #{token_with_audience("urn:example:service")}" })
    )
    bad_status, bad_headers, = gated.call(
      rack_env(headers: { "Authorization" => "Bearer #{token_with_audience("urn:example:other")}" })
    )

    expect(ok_status).to eq(200)
    expect(bad_status).to eq(401)
    expect(bad_headers["www-authenticate"]).to include('error="invalid_token"')
    expect(bad_headers["www-authenticate"]).not_to include("resource_metadata=")
  end

  it "12: anonymous request to configured path through TLS-terminating HTTP proxy advertises configured metadata URL" do
    gated = described_class.new(probe, verifier: real_verifier(resource_identifier: "https://api.example.com/mcp"))

    status, headers, = gated.call(rack_env(path: "/mcp", scheme: "http", host: "internal"))

    expect(status).to eq(401)
    expect(headers["www-authenticate"])
      .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"')
  end

  it "12a: anonymous requests to non-matching path or query omit resource_metadata" do
    gated = described_class.new(probe, verifier: real_verifier(resource_identifier: "https://api.example.com/mcp"))

    status1, headers1, = gated.call(rack_env(path: "/tools", scheme: "http", host: "internal"))
    status2, headers2, = gated.call(rack_env(path: "/mcp", query: "other=1", scheme: "http", host: "internal"))

    expect(status1).to eq(401)
    expect(headers1["www-authenticate"]).not_to include("resource_metadata=")
    expect(status2).to eq(401)
    expect(headers2["www-authenticate"]).not_to include("resource_metadata=")
  end

  it "12b: bare origin resource_identifier matches / for challenge but rejects trailing-slash aud" do
    gated = described_class.new(probe, verifier: real_verifier(resource_identifier: "https://api.example.com"))

    anon_status, anon_headers, = gated.call(rack_env(path: "/"))
    slash_token = token_with_audience("https://api.example.com/")
    tok_status, tok_headers, = gated.call(rack_env(path: "/", headers: { "Authorization" => "Bearer #{slash_token}" }))

    expect(anon_status).to eq(401)
    expect(anon_headers["www-authenticate"])
      .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"')
    expect(tok_status).to eq(401)
    expect(tok_headers["www-authenticate"]).to include(
      'error="invalid_token"',
      'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"'
    )
  end

  it "12c: spoofed Host and X-Forwarded-* headers do not alter the advertised metadata URL" do
    gated = described_class.new(probe, verifier: real_verifier(resource_identifier: "https://api.example.com/mcp"))

    status, headers, = gated.call(rack_env(
                                    path: "/mcp",
                                    host: "attacker.example",
                                    headers: {
                                      "X-Forwarded-Host" => "evil.example",
                                      "X-Forwarded-Proto" => "http"
                                    }
                                  ))

    expect(status).to eq(401)
    expect(headers["www-authenticate"])
      .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"')
  end

  it "12d: mounted handler compares path before in-app mount stripping (SCRIPT_NAME + PATH_INFO)" do
    gated = described_class.new(probe, verifier: real_verifier(resource_identifier: "https://api.example.com/app/mcp"))

    status, headers, = gated.call(rack_env(script_name: "/app", path: "/mcp"))

    expect(status).to eq(401)
    expect(headers["www-authenticate"])
      .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/app/mcp"')
  end

  it "13: combining resource_identifier and allow_any_audience raises ConfigurationError" do
    expect do
      real_verifier(resource_identifier: "https://api.example.com/mcp", allow_any_audience: true)
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "14: legacy audience list without multi_resource warns once naming resource_identifier " \
     "and retains audience check and legacy challenge" do
    bound = nil
    expect { bound = real_verifier(audiences: %w[resource-a resource-b]) }
      .to output(/warning: .*resource_identifier/).to_stderr
    gated = described_class.new(probe, verifier: bound)

    anon_status, anon_headers, = gated.call(rack_env(path: "/tools"))
    ok_status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{token_with_audience("resource-b")}" }))
    bad_status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{token_with_audience("resource-c")}" }))

    expect(anon_status).to eq(401)
    expect(anon_headers["www-authenticate"])
      .to include('resource_metadata="https://tool.example.com/.well-known/oauth-protected-resource"')
    expect(ok_status).to eq(200)
    expect(bad_status).to eq(401)
  end

  it "14a: legacy scalar audience without explicit mode warns once naming resource_identifier " \
     "and retains scalar check and legacy challenge" do
    bound = nil
    expect { bound = real_verifier(audiences: "https://api.example.com/mcp") }
      .to output(/warning: .*resource_identifier/).to_stderr
    gated = described_class.new(probe, verifier: bound)

    ok_status, = gated.call(
      rack_env(headers: { "Authorization" => "Bearer #{token_with_audience("https://api.example.com/mcp")}" })
    )
    bad_status, = gated.call(rack_env(headers: { "Authorization" => "Bearer #{foreign_resource_token}" }))

    expect(ok_status).to eq(200)
    expect(bad_status).to eq(401)
  end

  it "14b: multi_resource: true with scalar or zone map audiences raises ConfigurationError" do
    expect { real_verifier(multi_resource: true, audiences: "https://api.example.com/mcp") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
    expect { real_verifier(multi_resource: true, audiences: { "a" => "https://api.example.com/a" }) }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "15: valid token for configured HTTPS resource_identifier proceeds over internal HTTP proxy" do
    gated = described_class.new(probe, verifier: real_verifier(resource_identifier: "https://api.example.com/mcp"))
    token = token_with_audience("https://api.example.com/mcp")

    status, = gated.call(rack_env(path: "/mcp", scheme: "http", host: "internal",
                                  headers: { "Authorization" => "Bearer #{token}" }))

    expect(status).to eq(200)
    expect(probe.ran?).to be(true)
  end

  context "with per-zone resource mode" do
    let(:zone_map) do
      {
        "a" => "https://api.example.com/a/mcp",
        "b" => "https://api.example.com/b/mcp"
      }
    end
    let(:path_zone_resolver) do
      lambda do |env|
        match = env["PATH_INFO"].to_s.match(%r{\A/([^/]+)/mcp\z})
        match ? match[1] : nil
      end
    end

    def per_zone_middleware(resolver: path_zone_resolver, **options)
      verifier = Keycardai::OAuth::TokenVerifier.new(
        issuer: base_issuer,
        resource_identifiers_by_zone: zone_map,
        http_client: zone_http
      )
      described_class.new(probe, verifier: verifier, zone_resolver: resolver, **options)
    end

    it "16: resolves zone without a token for anonymous challenge and verifies zone token without warning" do
      gated = nil
      expect { gated = per_zone_middleware }.not_to output.to_stderr

      anon_status, anon_headers, = gated.call(rack_env(path: "/a/mcp"))
      token = token_with_audience("https://api.example.com/a/mcp",
                                  issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")
      ok_status, = gated.call(rack_env(path: "/a/mcp", headers: { "Authorization" => "Bearer #{token}" }))

      expect(anon_status).to eq(401)
      expect(anon_headers["www-authenticate"])
        .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/a/mcp"')
      expect(ok_status).to eq(200)
      expect(probe.ran?).to be(true)
    end

    it "16a: zone a token with zone b audience yields 401 invalid_token with zone a metadata URL" do
      gated = per_zone_middleware
      wrong_aud = token_with_audience("https://api.example.com/b/mcp",
                                      issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")

      status, headers, = gated.call(rack_env(path: "/a/mcp", headers: { "Authorization" => "Bearer #{wrong_aud}" }))

      expect(status).to eq(401)
      expect(headers["www-authenticate"]).to include(
        'error="invalid_token"',
        'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/a/mcp"'
      )
      expect(headers["www-authenticate"]).not_to include("/b/mcp")
    end

    it "16b: resource_identifiers_by_zone with resource_identifier or allow_any_audience raises ConfigurationError" do
      expect do
        Keycardai::OAuth::TokenVerifier.new(
          issuer: base_issuer,
          resource_identifier: "https://api.example.com/mcp",
          resource_identifiers_by_zone: zone_map,
          http_client: zone_http
        )
      end.to raise_error(Keycardai::OAuth::ConfigurationError)

      expect do
        Keycardai::OAuth::TokenVerifier.new(
          issuer: base_issuer,
          resource_identifiers_by_zone: zone_map,
          allow_any_audience: true,
          http_client: zone_http
        )
      end.to raise_error(Keycardai::OAuth::ConfigurationError)
    end

    it "16c: unresolved or unconfigured zone fails closed with 401 and no resource_metadata" do
      gated = per_zone_middleware

      none_status, none_headers, = gated.call(rack_env(path: "/other"))
      unknown_status, unknown_headers, = gated.call(rack_env(path: "/z/mcp"))

      expect(none_status).to eq(401)
      expect(none_headers["www-authenticate"]).to eq("Bearer")
      expect(unknown_status).to eq(401)
      expect(unknown_headers["www-authenticate"]).to eq("Bearer")
    end

    it "16d: per-zone mode with a token-only resolver raises ConfigurationError at construction" do
      token_only = ->(_env, _token) { "a" }

      expect { per_zone_middleware(resolver: token_only) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { per_zone_middleware(resolver: nil) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
    end

    it "publishes the resolved zone and locally verified auth even when an introspection-off request is denied" do
      gated = per_zone_middleware(required_scopes: ["mcp:admin"])
      anon_env = rack_env(path: "/a/mcp")
      token = token_with_audience(zone_map.fetch("a"), issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")
      denied_env = rack_env(path: "/a/mcp", headers: { "Authorization" => "Bearer #{token}" })

      expect(gated.call(anon_env).first).to eq(401)
      expect(anon_env[Keycardai::MCP::ENV_ZONE_ID]).to eq("a")
      expect(anon_env[Keycardai::MCP::ENV_AUTH_INFO]).to be_nil
      expect(gated.call(denied_env).first).to eq(403)
      expect(denied_env[Keycardai::MCP::ENV_ZONE_ID]).to eq("a")
      expect(denied_env[Keycardai::MCP::ENV_AUTH_INFO].issuer).to eq(zone_a_issuer)
    end
  end

  context "with shared discovery for token-keyed zones" do
    let(:shared_url) { "https://api.example.com/mcp" }
    let(:shared_zone_map) { { "a" => shared_url, "b" => shared_url } }

    it "17: advertises shared metadata URL anonymously and verifies tokens from both zones without warning" do
      verifier = nil
      expect do
        verifier = Keycardai::OAuth::TokenVerifier.new(
          issuer: base_issuer,
          multi_resource: true,
          resource_identifiers_by_zone: shared_zone_map,
          audiences: [shared_url],
          http_client: zone_http
        )
      end.not_to output.to_stderr
      gated = described_class.new(probe, verifier: verifier)

      anon_status, anon_headers, = gated.call(rack_env(path: "/mcp"))
      tok_a = token_with_audience(shared_url, issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")
      tok_b = token_with_audience(shared_url, issuer: zone_b_issuer, key: zone_b_key, kid: "kid-b")
      status_a, = gated.call(rack_env(path: "/mcp", headers: { "Authorization" => "Bearer #{tok_a}" }))
      status_b, = gated.call(rack_env(path: "/mcp", headers: { "Authorization" => "Bearer #{tok_b}" }))

      expect(anon_status).to eq(401)
      expect(anon_headers["www-authenticate"])
        .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"')
      expect(status_a).to eq(200)
      expect(status_b).to eq(200)
    end

    it "17a: shared discovery with differing zone identifiers raises ConfigurationError" do
      expect do
        Keycardai::OAuth::TokenVerifier.new(
          issuer: base_issuer,
          multi_resource: true,
          resource_identifiers_by_zone: { "a" => shared_url, "b" => "https://api.example.com/other" },
          audiences: [shared_url],
          http_client: zone_http
        )
      end.to raise_error(Keycardai::OAuth::ConfigurationError)
    end
  end

  context "with token introspection" do
    let(:resource) { "https://api.example.com/mcp" }
    let(:credential) { Keycardai::OAuth::ClientSecret.new("owner", "owner-secret") }
    let(:token) { token_with_audience(resource) }
    let(:verifier) { real_verifier(resource_identifier: resource) }

    def introspection_http(&response)
      FakeHTTPClient.new do |url, params|
        if params
          response.call(url)
        else
          issuer = url.delete_suffix("/.well-known/oauth-authorization-server")
          http_json({ "issuer" => issuer, "introspection_endpoint" => "#{issuer}/inspect-token" })
        end
      end
    end

    let(:http) { introspection_http { http_json({ "active" => true }) } }

    def gate(**options)
      middleware(introspect: true, credential: credential, http_client: http, **options)
    end

    it "18: calls introspection with the presented token and the owning Application credential" do
      status, = gate.call(bearer_env(token))

      expect(status).to eq(200)
      expect(http.calls.map(&:url)).to eq([
                                            "#{zone_issuer}/.well-known/oauth-authorization-server",
                                            "#{zone_issuer}/inspect-token"
                                          ])
      post = http.calls.last
      expect(post).to have_attributes(verb: :post, params: [["token", token]])
      expect(post.headers["Authorization"]).to eq(Keycardai::OAuth::HTTP.basic_authorization("owner", "owner-secret"))
      expect(Keycardai::MCP.auth_info(probe.seen_env).client_id).to eq("client_abc")
    end

    it "19: returns an invalid_token challenge with resource metadata for an inactive token" do
      http = introspection_http { http_json({ "active" => false }) }
      env = bearer_env(token)
      status, headers, = gate(http_client: http).call(env)

      expect(status).to eq(401)
      expect(headers["www-authenticate"]).to include('error="invalid_token"',
                                                     'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"')
      expect(Keycardai::MCP.auth_info(env)).to be_nil
      expect(probe.ran?).to be(false)
    end

    it "20: returns an unchallenged 503 for transport, HTTP, metadata, OAuth, and malformed-response failures" do
      clients = [
        introspection_http { raise Keycardai::OAuth::NetworkError, "connection refused" },
        introspection_http { http_json({}, status: 502) },
        FakeHTTPClient.new { http_json({ "issuer" => "https://wrong.test" }) },
        introspection_http { http_json({ "error" => "invalid_client" }, status: 401) },
        introspection_http { http_json({ "error" => "server_error" }, status: 500) },
        introspection_http { http_json({ "active" => "false" }) }
      ]

      clients.each do |client|
        expect { expect_unavailable(gate(http_client: client)) }.to output(/introspection failed/).to_stderr
      end
      expect(probe.ran?).to be(false)
    end

    def expect_unavailable(gated, presented_token = token)
      status, headers, body = gated.call(bearer_env(presented_token))
      expect(status).to eq(503)
      expect(headers).not_to have_key("www-authenticate")
      expect(body.join).to eq('{"error":"temporarily_unavailable"}')
    end

    it "21: skips introspection for an invalid token and when introspect is omitted or false" do
      expect(gate.call(bearer_env(foreign_resource_token)).first).to eq(401)
      expect(middleware(http_client: http).call(bearer_env(token)).first).to eq(200)
      expect(gate(introspect: false).call(bearer_env(token)).first).to eq(200)
      expect(http.calls).to be_empty
    end

    it "22: checks the same token twice and denies it after it becomes inactive" do
      results = [true, false]
      http = introspection_http { http_json({ "active" => results.shift }) }
      gated = gate(http_client: http)

      expect(gated.call(bearer_env(token)).first).to eq(200)
      expect(gated.call(bearer_env(token)).first).to eq(401)
      expect(http.calls.count { |call| call.verb == :post }).to eq(2)
      expect(http.calls.count { |call| call.verb == :get }).to eq(1)
    end

    it "23: rejects missing, non-client-authenticating, and unscoped multi-zone credentials at construction" do
      [nil, Object.new].each do |value|
        expect { gate(credential: value) }.to raise_error(Keycardai::OAuth::ConfigurationError, /client authentication/)
      end
      multi = real_verifier(issuers: [zone_issuer, zone_b_issuer], resource_identifier: resource)
      expect { described_class.new(probe, verifier: multi, introspect: true, credential: credential) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /one trusted issuer/)
      expect(http.calls).to be_empty
    end

    it "24: picks credentials by verified issuer and returns an unchallenged 503 for an unconfigured zone" do
      multi = real_verifier(issuers: [zone_issuer, zone_a_issuer, zone_b_issuer], resource_identifier: resource)
      zoned = Keycardai::OAuth::ClientSecret.new(zone_issuer => %w[owner secret], zone_a_issuer => %w[owner-a secret-a])
      gated = described_class.new(probe, verifier: multi, introspect: true, credential: zoned, http_client: http)
      tok_b = token_with_audience(resource, issuer: zone_b_issuer, key: zone_b_key, kid: "kid-b")
      tok_a = token_with_audience(resource, issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")

      expect { expect_unavailable(gated, tok_b) }.to output(/introspection failed/).to_stderr
      expect(http.calls).to be_empty
      expect(probe.ran?).to be(false)
      expect(gated.call(bearer_env(tok_a)).first).to eq(200)
      expect(http.calls.last.url).to eq("#{zone_a_issuer}/inspect-token")
      expect(http.calls.last.headers["Authorization"])
        .to eq(Keycardai::OAuth::HTTP.basic_authorization("owner-a", "secret-a"))
      expect(gated.call(bearer_env(token)).first).to eq(200)
      expect(http.calls.last.url).to eq("#{zone_issuer}/inspect-token")
    end

    it "refreshes introspection metadata when its configured TTL expires" do
      gated = gate(discovery_ttl: 0)

      expect(gated.call(bearer_env(token)).first).to eq(200)
      expect(gated.call(bearer_env(token)).first).to eq(200)
      expect(http.calls.map(&:verb)).to eq(%i[get post get post])
    end

    it "uses the advertised issuer for a credential keyed to its exact URL" do
      advertised_issuer = "#{zone_issuer}/"
      http = FakeHTTPClient.new do |_url, params|
        if params
          http_json({ "active" => true })
        else
          http_json({ "issuer" => advertised_issuer, "introspection_endpoint" => "#{zone_issuer}/inspect-token" })
        end
      end
      zoned = double("exact-issuer credential", issuers: [advertised_issuer])
      allow(zoned).to receive(:client_authentication) do |issuer:, endpoint:|
        unless issuer == advertised_issuer
          raise Keycardai::OAuth::ConfigurationError, "no credential configured for that issuer"
        end

        credential.client_authentication(issuer: issuer, endpoint: endpoint)
      end

      expect(gate(http_client: http, credential: zoned).call(bearer_env(token)).first).to eq(200)
      expect(http.calls.map(&:verb)).to eq(%i[get post])
    end

    it "paces discovery after an HTTP 503 with Retry-After" do
      unavailable = Keycardai::OAuth::HTTP::Response.new(status: 503, headers: { "retry-after" => "60" }, body: "")
      http = FakeHTTPClient.new { unavailable }
      gated = gate(http_client: http)

      expect { 2.times { expect_unavailable(gated) } }.to output(/introspection failed/).to_stderr
      expect(http.calls.map(&:verb)).to eq([:get])
    end

    it "25: returns insufficient_scope without introspection when a required scope is missing" do
      status, headers, = gate(required_scopes: ["mcp:admin"]).call(bearer_env(token))

      expect(status).to eq(403)
      expect(headers["www-authenticate"]).to include('error="insufficient_scope"')
      expect(http.calls).to be_empty
      expect(probe.ran?).to be(false)
    end

    it "introspects a stacked route using the zone resolved by the upstream per-zone gate" do
      upstream = Keycardai::OAuth::TokenVerifier.new(
        issuer: base_issuer, resource_identifiers_by_zone: { "a" => resource }, http_client: zone_http
      )
      route_verifier = real_verifier(issuers: zone_a_issuer, resource_identifier: resource)
      local = double("route verifier", issuers: route_verifier.issuers)
      presented = token_with_audience(resource, issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")
      expect(local).to receive(:verify_token).with(presented) { route_verifier.verify_token(presented) }
      route = described_class.new(probe, verifier: local, introspect: true, credential: credential, http_client: http)
      outer = described_class.new(route, verifier: upstream, zone_resolver: ->(_env) { "a" })

      expect(outer.call(bearer_env(presented)).first).to eq(200)
      expect(http.calls.last.url).to eq("#{zone_a_issuer}/inspect-token")
      expect(probe.ran?).to be(true)
    end

    it "rejects a stacked introspection route when its selected zone differs from the verified upstream zone" do
      upstream = Keycardai::OAuth::TokenVerifier.new(
        issuer: base_issuer, resource_identifiers_by_zone: { "a" => resource, "b" => resource }, http_client: zone_http
      )
      route_verifier = real_verifier(issuers: zone_a_issuer, resource_identifier: resource)
      local = double("route verifier", issuers: route_verifier.issuers)
      presented = token_with_audience(resource, issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")
      allow(local).to receive(:verify_token).with(presented) { route_verifier.verify_token(presented) }
      route = described_class.new(probe, verifier: local, zone_resolver: ->(_env) { "b" },
                                         introspect: true, credential: credential, http_client: http)
      outer = described_class.new(route, verifier: upstream, zone_resolver: ->(_env) { "a" })

      status, headers, = outer.call(bearer_env(presented))
      expect(status).to eq(401)
      expect(headers["www-authenticate"]).to include('error="invalid_token"')
      expect(http.calls).to be_empty
      expect(probe.ran?).to be(false)
    end

    it "uses the selected zone for a wrapped per-zone verifier on a stacked introspection route" do
      upstream = Keycardai::OAuth::TokenVerifier.new(
        issuer: base_issuer, resource_identifiers_by_zone: { "a" => resource }, http_client: zone_http
      )
      local = double("wrapped per-zone verifier", issuers: upstream.issuers)
      presented = token_with_audience(resource, issuer: zone_a_issuer, key: zone_a_key, kid: "kid-a")
      allow(local).to receive(:verify_token).with(presented) { upstream.verify_token(presented) }
      allow(local).to receive(:verify_token_for_zone).with(presented, "a") do
        upstream.verify_token_for_zone(presented, "a")
      end
      route = described_class.new(probe, verifier: local, zone_resolver: ->(_env) { "a" },
                                         introspect: true, credential: credential, http_client: http)
      outer = described_class.new(route, verifier: upstream, zone_resolver: ->(_env) { "a" })

      expect(outer.call(bearer_env(presented)).first).to eq(200)
      expect(local).to have_received(:verify_token_for_zone).with(presented, "a")
      expect(http.calls.last.url).to eq("#{zone_a_issuer}/inspect-token")
      expect(probe.ran?).to be(true)
    end

    it "re-verifies a stacked request without requiring an issuer on the upstream auth object" do
      upstream_auth = double("upstream auth", scopes: [])
      upstream = FakeVerifier.new(token => upstream_auth)
      outer = described_class.new(gate, verifier: upstream)

      expect(outer.call(bearer_env(token)).first).to eq(200)
      expect(http.calls.last.url).to eq("#{zone_issuer}/inspect-token")
      expect(probe.ran?).to be(true)
    end

    it "logs each distinct introspection failure once without logging the server body" do
      responses = [401, 401, 500]
      http = introspection_http do
        http_json({ "error" => "invalid_client", "error_description" => "sensitive" }, status: responses.shift)
      end
      gated = gate(http_client: http)

      expect { 3.times { expect_unavailable(gated) } }.to output(
        /\A(?!.*sensitive)[^\n]*HTTP 401[^\n]*\n[^\n]*HTTP 500[^\n]*\n\z/m
      ).to_stderr
    end

    it "logs the verified issuer and the error message without logging the bearer token" do
      http = introspection_http { raise Keycardai::OAuth::NetworkError, "connection refused for #{token}" }
      gated = gate(http_client: http)
      message = /\A[^\n]*#{Regexp.escape(zone_issuer)}[^\n]*connection refused for \[REDACTED\][^\n]*\n\z/

      expect { 2.times { expect_unavailable(gated) } }.to output(message).to_stderr
    end

    it "passes the configured timeout to introspection discovery and the token status request" do
      expect(http).to receive(:get).with("#{zone_issuer}/.well-known/oauth-authorization-server",
                                         hash_including(timeout: 2)).and_call_original
      expect(http).to receive(:post_form).with("#{zone_issuer}/inspect-token", [["token", token]],
                                               hash_including(timeout: 2)).and_call_original

      expect(gate(timeout: 2).call(bearer_env(token)).first).to eq(200)
    end

    it "rejects an HTTP client missing an introspection method only when introspection is enabled" do
      get_only = double("GET-only HTTP client", get: nil)
      post_only = double("POST-only HTTP client", post_form: nil)

      [get_only, post_only].each do |client|
        expect { gate(http_client: client) }.to raise_error(Keycardai::OAuth::ConfigurationError, /get and post_form/)
      end
      expect(middleware(http_client: get_only).call(bearer_env(token)).first).to eq(200)
    end
  end

  it "Integration 2: token issued for another resource is 401 when resource_identifier is configured" do
    provider = Keycardai::MCP::AuthProvider.new(
      zone_url: zone_issuer,
      resource_identifier: "https://api.example.com/mcp",
      http_client: zone_http
    )
    gated = described_class.new(probe, verifier: provider.token_verifier)

    status, headers, = gated.call(
      rack_env(path: "/mcp", headers: { "Authorization" => "Bearer #{foreign_resource_token}" })
    )

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include('error="invalid_token"')
    expect(probe.ran?).to be(false)
  end

  # Infrastructure failures: the zone's keys or metadata could not be fetched,
  # so the token was never judged. 503 with no challenge, so the client keeps
  # its token and retries instead of signing in again.
  def failing_zone(jwks_status: nil, discovery_status: nil, raise_on: nil)
    FakeHTTPClient.new do |url, _params|
      raise Keycardai::OAuth::NetworkError, "connection refused" if raise_on && url.include?(raise_on)

      case url
      when "#{zone_issuer}/.well-known/oauth-authorization-server"
        next http_json({}, status: discovery_status) if discovery_status

        http_json({ "issuer" => zone_issuer, "jwks_uri" => "#{zone_issuer}/.well-known/jwks.json",
                    "token_endpoint" => "#{zone_issuer}/oauth/token" })
      when "#{zone_issuer}/.well-known/jwks.json"
        http_json({ "keys" => [] }, status: jwks_status || 200)
      else
        http_json({}, status: 404)
      end
    end
  end

  def zone_token(kid: "kid-1")
    claims = { "iss" => zone_issuer, "sub" => "usr_123", "aud" => "https://tool.example.com",
               "exp" => Time.now.to_i + 300, "iat" => Time.now.to_i,
               "client_id" => "client_abc", "scope" => "mcp:tools" }
    JWT.encode(claims, zone_key, "RS256", { "kid" => kid })
  end

  def bearer_env(token)
    rack_env(headers: { "Authorization" => "Bearer #{token}" })
  end

  def unavailable_middleware(http)
    verifier = Keycardai::OAuth::TokenVerifier.new(issuers: zone_issuer,
                                                   resource_identifier: "https://tool.example.com",
                                                   http_client: http)
    described_class.new(probe, verifier: verifier)
  end

  shared_examples "temporarily unavailable" do
    it "answers 503 temporarily_unavailable with no challenge and does not run the app" do
      status, headers, body = unavailable_middleware(http).call(bearer_env(zone_token))

      expect(status).to eq(503)
      expect(headers).not_to have_key("www-authenticate")
      expect(JSON.parse(body.join)).to eq({ "error" => "temporarily_unavailable" })
      expect(probe.ran?).to be(false)
    end
  end

  context "when the JWKS fetch returns an error status (JWKSFetchError)" do
    let(:http) { failing_zone(jwks_status: 503) }
    include_examples "temporarily unavailable"
  end

  context "when the JWKS fetch fails at the transport (JWKSFetchError wrapping NetworkError)" do
    let(:http) { failing_zone(raise_on: "jwks.json") }
    include_examples "temporarily unavailable"
  end

  context "when authorization-server discovery returns an error status (JWKSDiscoveryError wrapping HTTPError)" do
    let(:http) { failing_zone(discovery_status: 500) }
    include_examples "temporarily unavailable"
  end

  context "when authorization-server discovery fails at the transport (JWKSDiscoveryError wrapping NetworkError)" do
    let(:http) { failing_zone(raise_on: "oauth-authorization-server") }
    include_examples "temporarily unavailable"
  end

  it "a kid absent from a JWKS that loaded is an invalid token: 401 invalid_token with a challenge" do
    jwk = JWT::JWK.new(zone_key.public_key, { kid: "kid-1", use: "sig", alg: "RS256" })
    http = FakeHTTPClient.new do |url, _params|
      case url
      when "#{zone_issuer}/.well-known/oauth-authorization-server"
        http_json({ "issuer" => zone_issuer, "jwks_uri" => "#{zone_issuer}/.well-known/jwks.json",
                    "token_endpoint" => "#{zone_issuer}/oauth/token" })
      when "#{zone_issuer}/.well-known/jwks.json"
        http_json({ "keys" => [jwk.export.transform_keys(&:to_s)] })
      end
    end

    status, headers, = unavailable_middleware(http).call(bearer_env(zone_token(kid: "kid-rotated")))

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include('error="invalid_token"')
    expect(probe.ran?).to be(false)
  end

  it "a token that fails signature verification against loaded keys is 401 invalid_token" do
    other_key = OpenSSL::PKey::RSA.new(2048)
    claims = { "iss" => zone_issuer, "sub" => "usr_123", "aud" => "https://tool.example.com",
               "exp" => Time.now.to_i + 300, "iat" => Time.now.to_i, "client_id" => "client_abc" }
    forged = JWT.encode(claims, other_key, "RS256", { "kid" => "kid-1" })

    status, headers, = unavailable_middleware(zone_http).call(bearer_env(forged))

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include('error="invalid_token"')
  end

  it "rejects construction without a verifier" do
    expect { described_class.new(probe, verifier: nil) }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "matches the bearer scheme case-insensitively" do
    expect(middleware.call(rack_env(headers: { "Authorization" => "bearer at_valid" })).first).to eq(200)
  end
end
