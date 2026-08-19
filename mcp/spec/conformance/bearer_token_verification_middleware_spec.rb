# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec
# specs/server-bearer-auth/bearer-token-verification-middleware.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::MCP::RequireBearerAuth do
  let(:probe) { ProbeApp.new }
  let(:verifier) { FakeVerifier.new("at_valid" => access_token) }

  def middleware(**options)
    described_class.new(probe, verifier: verifier, **options)
  end

  it "1: a missing Authorization header yields 401 with a resource_metadata challenge" do
    status, headers, = middleware.call(rack_env)

    expect(status).to eq(401)
    expect(headers["www-authenticate"])
      .to include('resource_metadata="https://tool.example.com/.well-known/oauth-protected-resource"')
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

  it "rejects construction without a verifier" do
    expect { described_class.new(probe, verifier: nil) }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "matches the bearer scheme case-insensitively" do
    expect(middleware.call(rack_env(headers: { "Authorization" => "bearer at_valid" })).first).to eq(200)
  end
end
