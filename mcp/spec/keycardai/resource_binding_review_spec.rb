# frozen_string_literal: true

# Regression cases for the resource-binding review of keycard-sdk-spec#151:
# zone-mode grants exchange at the verified zone, stacked gates with their own
# binding re-verify, and explicit bindings enforce audience on custom verifiers.
RSpec.describe "Resource binding review fixes" do
  let(:probe) { ProbeApp.new }

  def zone_token(iss:, aud:, scope: "read")
    claims = { "iss" => iss, "sub" => "usr_123", "aud" => aud, "exp" => Time.now.to_i + 300,
               "iat" => Time.now.to_i, "client_id" => "client_abc", "scope" => scope }
    Keycardai::OAuth::AccessToken.new(token: "at_caller", claims: claims)
  end

  describe "grant in zone modes" do
    let(:zone) { MiniZone.new(issuer: "https://acme.keycard.test") }
    let(:http) do
      FakeHTTPClient.new do |url, params|
        next http_json(zone.metadata) if url == zone.metadata_url
        next http_json({ "access_token" => "at_#{params["resource"]}" }) if url == zone.token_url

        http_json({ "error" => "not_found" }, status: 404)
      end
    end

    def provider(**options)
      Keycardai::MCP::AuthProvider.new(zone_url: "https://keycard.test", client_id: "cid", client_secret: "cs",
                                       http_client: http, **options)
    end

    it "exchanges at the verified zone's issuer in per-zone mode, not the base issuer" do
      grant = provider(resource_identifiers_by_zone: { "acme" => "https://api.example.com/acme/mcp" })
              .grant("https://a.test").new(probe)
      env = rack_env.merge(
        Keycardai::MCP::ENV_AUTH_INFO => zone_token(iss: zone.issuer, aud: "https://api.example.com/acme/mcp"),
        Keycardai::MCP::ENV_ZONE_ID => "acme"
      )

      status, = grant.call(env)

      expect(status).to eq(200)
      expect(Keycardai::MCP.access_context(probe.seen_env).access("https://a.test").access_token)
        .to eq("at_https://a.test")
      expect(http.calls.map(&:url)).to all(start_with(zone.issuer))
    end

    it "exchanges at the token's zone in shared discovery mode" do
      shared = "https://api.example.com/mcp"
      grant = provider(resource_identifiers_by_zone: { "acme" => shared, "beta" => shared },
                       multi_resource: true, audiences: [shared]).grant("https://a.test").new(probe)
      env = rack_env.merge(Keycardai::MCP::ENV_AUTH_INFO => zone_token(iss: zone.issuer, aud: shared))

      status, = grant.call(env)

      expect(status).to eq(200)
      expect(http.calls.map(&:url)).to all(start_with(zone.issuer))
    end

    it "rejects a token from an unconfigured zone without exchanging at the base issuer" do
      shared = "https://api.example.com/mcp"
      grant = provider(resource_identifiers_by_zone: { "acme" => shared, "beta" => shared },
                       multi_resource: true, audiences: [shared]).grant("https://a.test").new(probe)
      env = rack_env.merge(Keycardai::MCP::ENV_AUTH_INFO => zone_token(iss: "https://other.keycard.test", aud: shared))

      status, = grant.call(env)

      expect(status).to eq(401)
      expect(probe.ran?).to be(false)
      expect(http.calls).to be_empty
    end
  end

  describe "stacked gates" do
    it "re-verifies with the inner gate's own binding when it differs from the upstream one" do
      verifier = FakeVerifier.new("at_a" => zone_token(iss: "https://acme.test", aud: "https://api.example.com/a"))
      inner = Keycardai::MCP::RequireBearerAuth.new(probe, verifier: verifier, required_scopes: ["read"],
                                                           resource_identifier: "https://api.example.com/b")
      outer = Keycardai::MCP::RequireBearerAuth.new(inner, verifier: verifier,
                                                           resource_identifier: "https://api.example.com/a")

      status, headers, = outer.call(rack_env(path: "/b", headers: { "Authorization" => "Bearer at_a" }))

      expect(status).to eq(401)
      expect(headers["www-authenticate"]).to include('error="invalid_token"')
      expect(probe.ran?).to be(false)
    end
  end

  describe "custom verifier audience" do
    it "rejects a token for another resource when the verifier ignores audiences" do
      verifier = FakeVerifier.new("at_other" => zone_token(iss: "https://acme.test", aud: "https://other.example.com"))
      gate = Keycardai::MCP::RequireBearerAuth.new(probe, verifier: verifier,
                                                          resource_identifier: "https://api.example.com/mcp")

      status, headers, = gate.call(rack_env(headers: { "Authorization" => "Bearer at_other" }))

      expect(status).to eq(401)
      expect(headers["www-authenticate"]).to include('error="invalid_token"')
      expect(probe.ran?).to be(false)
    end
  end
end
