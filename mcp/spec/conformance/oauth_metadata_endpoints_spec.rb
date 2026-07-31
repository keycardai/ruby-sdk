# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec
# specs/server-bearer-auth/oauth-metadata-endpoints.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::MCP::MetadataApp do
  let(:zone) { MiniZone.new }

  def upstream(metadata = zone.metadata, status: 200)
    FakeHTTPClient.new { |_url, _params| http_json(metadata, status: status) }
  end

  def app(**options)
    described_class.new(issuer: zone.issuer, http_client: upstream, **options)
  end

  it "1: the protected-resource document derives resource from the request origin" do
    response = app.call(rack_env(path: "/.well-known/oauth-protected-resource"))

    expect(response.first).to eq(200)
    expect(parse_body(response)).to include(
      "resource" => "https://tool.example.com",
      "authorization_servers" => [zone.issuer]
    )
    expect(response[1]).to include("access-control-allow-origin" => "*")
  end

  it "1b: path insertion identifies a sub-path mount" do
    response = app.call(rack_env(path: "/.well-known/oauth-protected-resource/mcp"))

    expect(parse_body(response)["resource"]).to eq("https://tool.example.com/mcp")
  end

  it "2: configured scopes_supported and resource_name appear in the document" do
    configured = app(scopes_supported: ["mcp:tools"], resource_name: "My Tool")

    document = parse_body(configured.call(rack_env(path: "/.well-known/oauth-protected-resource")))

    expect(document).to include("scopes_supported" => ["mcp:tools"], "resource_name" => "My Tool")
  end

  it "3: the 2025-03-26 MCP protocol version rewrites authorization_servers to the request origin" do
    response = app.call(rack_env(path: "/.well-known/oauth-protected-resource",
                                 headers: { "MCP-Protocol-Version" => "2025-03-26" }))

    expect(parse_body(response)["authorization_servers"]).to eq(["https://tool.example.com"])
  end

  it "4: the AS proxy returns the upstream document with resource=<origin> on the authorization_endpoint" do
    existing = zone.metadata("authorization_endpoint" => "#{zone.issuer}/oauth/authorize?resource=stale&keep=1")
    proxied = described_class.new(issuer: zone.issuer, http_client: upstream(existing))

    response = proxied.call(rack_env(path: "/.well-known/oauth-authorization-server"))
    document = parse_body(response)

    expect(response.first).to eq(200)
    endpoint = URI(document["authorization_endpoint"])
    params = URI.decode_www_form(endpoint.query).to_h
    expect(params).to include("resource" => "https://tool.example.com", "keep" => "1")
    expect(URI.decode_www_form(endpoint.query).count { |name, _| name == "resource" }).to eq(1)
  end

  it "5: an upstream failure yields 502 Bad Gateway" do
    failing = described_class.new(issuer: zone.issuer, http_client: upstream({}, status: 500))

    expect(failing.call(rack_env(path: "/.well-known/oauth-authorization-server")).first).to eq(502)
  end

  it "6: jwks.json serves the configured key set and 404s when unset" do
    jwks = { "keys" => [{ "kty" => "RSA", "kid" => "kid-1" }] }
    with_keys = app(public_jwks: jwks)

    expect(parse_body(with_keys.call(rack_env(path: "/.well-known/jwks.json")))).to eq(jwks)
    expect(app.call(rack_env(path: "/.well-known/jwks.json")).first).to eq(404)
  end

  it "answers the CORS preflight" do
    status, headers, = app.call(rack_env(path: "/.well-known/oauth-protected-resource", method: "OPTIONS"))

    expect(status).to eq(204)
    expect(headers["access-control-allow-origin"]).to eq("*")
  end
end
