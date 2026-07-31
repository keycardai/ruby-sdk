# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec
# specs/server-bearer-auth/route-level-auth-gating.md. Gating in Ruby follows
# the TS/Go idiom: the verification middleware re-applied with a
# required_scopes set. Each example maps to a row of the spec's Unit Tests table.
RSpec.describe "Route-level auth gating" do
  let(:probe) { ProbeApp.new }
  let(:verifier) { FakeVerifier.new("at_rw" => access_token(scope: "read write")) }

  def gate(app, *scopes)
    Keycardai::MCP::RequireBearerAuth.new(app, verifier: verifier, required_scopes: scopes)
  end

  it "1: an authenticated caller holding all required scopes runs the handler" do
    status, = gate(probe, "read", "write").call(rack_env(headers: { "Authorization" => "Bearer at_rw" }))

    expect(status).to eq(200)
    expect(probe.ran?).to be(true)
  end

  it "2: an anonymous caller on a gated route gets 401 with a resource_metadata challenge" do
    status, headers, = gate(probe, "read").call(rack_env)

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include("resource_metadata=")
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
end
