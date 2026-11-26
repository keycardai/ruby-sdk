# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec
# specs/server-bearer-auth/oauth-metadata-endpoints.md (spec-version 3).
# Each example maps to a row of the spec's Unit Tests and Integration Tests tables.
RSpec.describe Keycardai::MCP::MetadataApp do
  let(:zone) { MiniZone.new }
  let(:base_issuer) { "https://keycard.cloud" }
  let(:zone_a_meta) do
    {
      "issuer" => "https://a.keycard.cloud",
      "authorization_endpoint" => "https://a.keycard.cloud/oauth/authorize",
      "token_endpoint" => "https://a.keycard.cloud/oauth/token",
      "jwks_uri" => "https://a.keycard.cloud/.well-known/jwks.json"
    }
  end
  let(:zone_b_meta) do
    {
      "issuer" => "https://b.keycard.cloud",
      "authorization_endpoint" => "https://b.keycard.cloud/oauth/authorize",
      "token_endpoint" => "https://b.keycard.cloud/oauth/token",
      "jwks_uri" => "https://b.keycard.cloud/.well-known/jwks.json"
    }
  end

  def upstream(metadata = zone.metadata, status: 200)
    FakeHTTPClient.new { |_url, _params| http_json(metadata, status: status) }
  end

  def app(resource_identifier: "https://api.example.com", **options)
    described_class.new(
      issuer: zone.issuer,
      resource_identifier: resource_identifier,
      http_client: upstream,
      **options
    )
  end

  it "1: serves configured HTTPS resource_identifier verbatim with authorization_servers = [issuer]" do
    response = app(resource_identifier: "https://api.example.com")
               .call(rack_env(path: "/.well-known/oauth-protected-resource"))

    expect(response.first).to eq(200)
    expect(parse_body(response)).to include(
      "resource" => "https://api.example.com",
      "authorization_servers" => [zone.issuer]
    )
    expect(response[1]).to include("access-control-allow-origin" => "*")
  end

  it "2: configured scopes_supported and resource_name appear in the document" do
    configured = app(scopes_supported: ["mcp:tools"], resource_name: "My Tool")

    document = parse_body(configured.call(rack_env(path: "/.well-known/oauth-protected-resource")))

    expect(document).to include("scopes_supported" => ["mcp:tools"], "resource_name" => "My Tool")
  end

  it "3: MCP-Protocol-Version 2025-03-26 yields the same protected-resource document as no header" do
    without_header = parse_body(app.call(rack_env(path: "/.well-known/oauth-protected-resource")))
    with_header = parse_body(app.call(rack_env(path: "/.well-known/oauth-protected-resource",
                                               headers: { "MCP-Protocol-Version" => "2025-03-26" })))

    expect(with_header).to eq(without_header)
    expect(with_header["authorization_servers"]).to eq([zone.issuer])
  end

  it "4: the AS proxy returns the upstream document unmodified, existing query included" do
    endpoint = "#{zone.issuer}/oauth/authorize?resource=stale&keep=1"
    existing = zone.metadata("authorization_endpoint" => endpoint)
    proxied = described_class.new(issuer: zone.issuer, resource_identifier: "https://api.example.com",
                                  http_client: upstream(existing))

    response = proxied.call(rack_env(path: "/.well-known/oauth-authorization-server"))
    document = parse_body(response)

    expect(response.first).to eq(200)
    expect(document).to eq(existing)
    expect(document["authorization_endpoint"]).to eq(endpoint)
  end

  context "with per-zone AS metadata proxy" do
    let(:zone_map) do
      {
        "a" => "https://api.example.com/a/mcp",
        "b" => "https://api.example.com/b/mcp"
      }
    end
    let(:fetched_urls) { [] }
    let(:zone_http) do
      FakeHTTPClient.new do |url, _params|
        fetched_urls << url
        case url
        when "https://a.keycard.cloud/.well-known/oauth-authorization-server"
          http_json(zone_a_meta)
        when "https://b.keycard.cloud/.well-known/oauth-authorization-server"
          http_json(zone_b_meta)
        else
          http_json({}, status: 404)
        end
      end
    end
    let(:zone_app) do
      described_class.new(issuer: base_issuer, resource_identifiers_by_zone: zone_map, http_client: zone_http)
    end

    it "4a: fetches zone-scoped AS metadata for configured zones without touching the base issuer" do
      resp_a = zone_app.call(rack_env(path: "/.well-known/oauth-authorization-server/a"))
      resp_b = zone_app.call(rack_env(path: "/.well-known/oauth-authorization-server/b"))

      expect(resp_a.first).to eq(200)
      expect(parse_body(resp_a)).to eq(zone_a_meta)
      expect(resp_b.first).to eq(200)
      expect(parse_body(resp_b)).to eq(zone_b_meta)
      expect(fetched_urls).to eq([
                                   "https://a.keycard.cloud/.well-known/oauth-authorization-server",
                                   "https://b.keycard.cloud/.well-known/oauth-authorization-server"
                                 ])
    end

    it "4b: returns 404 with no upstream fetch for bare AS path or unconfigured zone" do
      bare = zone_app.call(rack_env(path: "/.well-known/oauth-authorization-server"))
      unknown = zone_app.call(rack_env(path: "/.well-known/oauth-authorization-server/unknown"))

      expect(bare.first).to eq(404)
      expect(unknown.first).to eq(404)
      expect(fetched_urls).to be_empty
    end

    it "Integration 2: proxied zone AS metadata issuer matches the zone protected-resource document" do
      pr_doc = parse_body(zone_app.call(rack_env(path: "/.well-known/oauth-protected-resource/a/mcp")))
      as_doc = parse_body(zone_app.call(rack_env(path: "/.well-known/oauth-authorization-server/a")))

      expect(as_doc).to eq(zone_a_meta)
      expect(pr_doc["authorization_servers"]).to eq([as_doc["issuer"]])
    end
  end

  it "5: an upstream failure yields 502 Bad Gateway" do
    failing = described_class.new(issuer: zone.issuer, resource_identifier: "https://api.example.com",
                                  http_client: upstream({}, status: 500))

    expect(failing.call(rack_env(path: "/.well-known/oauth-authorization-server")).first).to eq(502)
  end

  it "6: jwks.json serves the configured key set and 404s when unset" do
    jwks = { "keys" => [{ "kty" => "RSA", "kid" => "kid-1" }] }
    with_keys = app(public_jwks: jwks)

    expect(parse_body(with_keys.call(rack_env(path: "/.well-known/jwks.json")))).to eq(jwks)
    expect(app.call(rack_env(path: "/.well-known/jwks.json")).first).to eq(404)
  end

  it "7: serves configured HTTPS resource verbatim behind a TLS-terminating HTTP proxy" do
    configured = app(resource_identifier: "https://api.example.com/mcp")

    response = configured.call(rack_env(
                                 path: "/.well-known/oauth-protected-resource/mcp",
                                 scheme: "http",
                                 host: "internal"
                               ))

    expect(response.first).to eq(200)
    expect(parse_body(response)["resource"]).to eq("https://api.example.com/mcp")
  end

  it "8: URN, multi_resource, and allow_any_audience do not register a protected-resource route" do
    urn_app = described_class.new(issuer: zone.issuer, resource_identifier: "urn:example:service",
                                  http_client: upstream)
    multi_app = described_class.new(issuer: zone.issuer, multi_resource: true, http_client: upstream)
    any_app = described_class.new(issuer: zone.issuer, allow_any_audience: true, http_client: upstream)

    [urn_app, multi_app, any_app].each do |handler|
      expect(handler.call(rack_env(path: "/.well-known/oauth-protected-resource")).first).to eq(404)
    end
  end

  it "8a: standalone handler with multi_resource or allow_any_audience emits no warning and keeps AS and JWKS" do
    jwks = { "keys" => [{ "kty" => "RSA", "kid" => "kid-1" }] }
    multi_app = nil
    any_app = nil
    expect do
      multi_app = described_class.new(issuer: zone.issuer, multi_resource: true,
                                      public_jwks: jwks, http_client: upstream)
      any_app = described_class.new(issuer: zone.issuer, allow_any_audience: true,
                                    public_jwks: jwks, http_client: upstream)
    end.not_to output.to_stderr

    [multi_app, any_app].each do |handler|
      expect(handler.call(rack_env(path: "/.well-known/oauth-protected-resource")).first).to eq(404)
      expect(handler.call(rack_env(path: "/.well-known/oauth-authorization-server")).first).to eq(200)
      expect(handler.call(rack_env(path: "/.well-known/jwks.json")).first).to eq(200)
    end
  end

  it "8b: conflicting mode options raise ConfigurationError at construction" do
    zone_map = { "a" => "https://api.example.com/a/mcp" }

    expect { described_class.new(issuer: zone.issuer, multi_resource: true, allow_any_audience: true) }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
    expect do
      described_class.new(issuer: base_issuer, resource_identifier: "https://api.example.com/mcp",
                          resource_identifiers_by_zone: zone_map)
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
    expect do
      described_class.new(issuer: zone.issuer, resource_identifier: "https://api.example.com/mcp",
                          multi_resource: true)
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
    expect do
      described_class.new(issuer: zone.issuer, resource_identifier: "https://api.example.com/mcp",
                          allow_any_audience: true)
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
    expect do
      described_class.new(issuer: base_issuer, resource_identifiers_by_zone: zone_map, allow_any_audience: true)
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "8c: standalone handler without explicit mode warns once naming resource_identifier " \
     "and retains legacy discovery" do
    legacy = nil
    expect { legacy = described_class.new(issuer: zone.issuer, http_client: upstream) }
      .to output(/warning: .*resource_identifier/).to_stderr

    response = legacy.call(rack_env(path: "/.well-known/oauth-protected-resource/mcp"))
    expect(response.first).to eq(200)
    expect(parse_body(response)["resource"]).to eq("https://tool.example.com/mcp")
  end

  it "9: two single-resource endpoints on the same host each serve only their own resource string" do
    app_a = app(resource_identifier: "https://api.example.com/a/mcp")
    app_b = app(resource_identifier: "https://api.example.com/b/mcp")

    doc_a = parse_body(app_a.call(rack_env(path: "/.well-known/oauth-protected-resource/a/mcp")))
    doc_b = parse_body(app_b.call(rack_env(path: "/.well-known/oauth-protected-resource/b/mcp")))

    expect(doc_a["resource"]).to eq("https://api.example.com/a/mcp")
    expect(doc_b["resource"]).to eq("https://api.example.com/b/mcp")
    expect(app_a.call(rack_env(path: "/.well-known/oauth-protected-resource/b/mcp")).first).to eq(404)
  end

  it "9a: per-zone map derives zone issuers and serves each zone's protected-resource document without warning" do
    zone_app = nil
    expect do
      zone_app = described_class.new(
        issuer: base_issuer,
        resource_identifiers_by_zone: {
          "a" => "https://api.example.com/a/mcp",
          "b" => "https://api.example.com/b/mcp"
        },
        http_client: upstream
      )
    end.not_to output.to_stderr

    resp_a = zone_app.call(rack_env(path: "/.well-known/oauth-protected-resource/a/mcp"))
    resp_b = zone_app.call(rack_env(path: "/.well-known/oauth-protected-resource/b/mcp"))

    expect(resp_a.first).to eq(200)
    expect(parse_body(resp_a)).to include(
      "resource" => "https://api.example.com/a/mcp",
      "authorization_servers" => ["https://a.keycard.cloud"]
    )
    expect(resp_b.first).to eq(200)
    expect(parse_body(resp_b)).to include(
      "resource" => "https://api.example.com/b/mcp",
      "authorization_servers" => ["https://b.keycard.cloud"]
    )
  end

  it "9b: zone map with HTTP(S) identifier and no base issuer raises ConfigurationError" do
    expect do
      described_class.new(resource_identifiers_by_zone: { "a" => "https://api.example.com/a/mcp" })
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "9c: shared discovery publishes one document listing all derived zone issuers" do
    shared = nil
    expect do
      shared = described_class.new(
        issuer: base_issuer,
        multi_resource: true,
        resource_identifiers_by_zone: {
          "a" => "https://api.example.com/mcp",
          "b" => "https://api.example.com/mcp"
        },
        http_client: upstream
      )
    end.not_to output.to_stderr

    response = shared.call(rack_env(path: "/.well-known/oauth-protected-resource/mcp"))

    expect(response.first).to eq(200)
    expect(parse_body(response)).to include(
      "resource" => "https://api.example.com/mcp",
      "authorization_servers" => ["https://a.keycard.cloud", "https://b.keycard.cloud"]
    )
  end

  it "9d: shared discovery with differing zone identifiers raises ConfigurationError" do
    expect do
      described_class.new(
        issuer: base_issuer,
        multi_resource: true,
        resource_identifiers_by_zone: {
          "a" => "https://api.example.com/mcp",
          "b" => "https://api.example.com/other"
        }
      )
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "10: mounted handler with root routing or forwarding serves host-root well-known URL verbatim" do
    mounted = app(
      resource_identifier: "https://api.example.com/app/mcp",
      mount_path: "/app",
      root_metadata_forwarded: true
    )

    response = mounted.call(rack_env(path: "/.well-known/oauth-protected-resource/app/mcp"))

    expect(response.first).to eq(200)
    expect(parse_body(response)["resource"]).to eq("https://api.example.com/app/mcp")
  end

  it "10a: mounted handler without root routing or forwarding raises ConfigurationError" do
    expect do
      app(resource_identifier: "https://api.example.com/app/mcp", mount_path: "/app")
    end.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "answers the CORS preflight" do
    status, headers, = app.call(rack_env(path: "/.well-known/oauth-protected-resource", method: "OPTIONS"))

    expect(status).to eq(204)
    expect(headers["access-control-allow-origin"]).to eq("*")
  end
end
