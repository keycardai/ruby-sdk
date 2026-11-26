# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec
# specs/server-bearer-auth/route-level-auth-gating.md (spec-version 2).
# Gating in Ruby is the verification middleware re-applied with a
# required_scopes set, reusing the upstream middleware's resource binding.
RSpec.describe "Route-level auth gating" do
  let(:probe) { ProbeApp.new }
  let(:verifier) { FakeVerifier.new("at_rw" => access_token(scope: "read write")) }

  def gate(app, *scopes, **options)
    Keycardai::MCP::RequireBearerAuth.new(app, verifier: verifier, required_scopes: scopes, **options)
  end

  it "1: an authenticated caller holding all required scopes runs the handler" do
    status, = gate(probe, "read", "write").call(rack_env(headers: { "Authorization" => "Bearer at_rw" }))

    expect(status).to eq(200)
    expect(probe.ran?).to be(true)
  end

  it "2: an anonymous caller on a gated route requesting the configured path gets 401 with its metadata URL" do
    gated = gate(probe, "read", resource_identifier: "https://api.example.com/mcp")

    status, headers, = gated.call(rack_env(path: "/mcp"))

    expect(status).to eq(401)
    expect(headers["www-authenticate"])
      .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"')
  end

  it "2a: anonymous caller requesting / with bare origin resource_identifier gets host-root metadata URL" do
    gated = gate(probe, "read", resource_identifier: "https://api.example.com")

    status, headers, = gated.call(rack_env(path: "/"))

    expect(status).to eq(401)
    expect(headers["www-authenticate"])
      .to eq('Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"')
  end

  it "3: an authenticated caller missing a required scope gets 403 insufficient_scope" do
    status, headers, = gate(probe, "admin").call(rack_env(headers: { "Authorization" => "Bearer at_rw" }))

    expect(status).to eq(403)
    expect(headers["www-authenticate"]).to include('error="insufficient_scope"')
  end

  it "4: gating on authentication alone (no scopes) runs the handler for any valid token" do
    status, = gate(probe).call(rack_env(headers: { "Authorization" => "Bearer at_rw" }))

    expect(status).to eq(200)
  end

  it "5: two stacked gates pass a caller holding the union of their scopes" do
    stacked = gate(gate(probe, "write"), "read")

    status, = stacked.call(rack_env(headers: { "Authorization" => "Bearer at_rw" }))

    expect(status).to eq(200)
    expect(probe.ran?).to be(true)
  end

  it "6: valid caller lacking a scope on a non-matching path behind an HTTP proxy gets 403 without resource_metadata" do
    inner = gate(probe, "admin")
    outer = Keycardai::MCP::RequireBearerAuth.new(
      inner,
      verifier: verifier,
      resource_identifier: "https://api.example.com/mcp"
    )

    status, headers, = outer.call(rack_env(
                                    path: "/tools",
                                    scheme: "http",
                                    host: "internal",
                                    headers: { "Authorization" => "Bearer at_rw" }
                                  ))

    expect(status).to eq(403)
    expect(headers["www-authenticate"]).to include('error="insufficient_scope"')
    expect(headers["www-authenticate"]).not_to include("resource_metadata=")
  end

  it "7: verifier-only or URN upstream binding emits 401 Bearer without resource_metadata" do
    urn_gate = gate(probe, "read", resource_identifier: "urn:example:service")
    multi_gate = gate(probe, "read", multi_resource: true, audiences: ["https://api.example.com/mcp"])
    any_gate = gate(probe, "read", allow_any_audience: true)

    [urn_gate, multi_gate, any_gate].each do |handler|
      status, headers, = handler.call(rack_env(path: "/mcp"))

      expect(status).to eq(401)
      expect(headers["www-authenticate"]).to eq("Bearer")
    end
  end
end
