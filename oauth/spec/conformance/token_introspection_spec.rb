# frozen_string_literal: true

require "tmpdir"

# Conformance suite for keycard-sdk-spec specs/oauth-client/token-introspection.md.
RSpec.describe Keycardai::OAuth do
  let(:issuer) { "https://zone.test" }
  let(:discovery_url) { "#{issuer}/.well-known/oauth-authorization-server" }
  let(:endpoint) { "#{issuer}/custom/introspect" }
  let(:metadata) { described_class::AuthorizationServerMetadata.new(issuer: issuer, introspection_endpoint: endpoint) }
  let(:discovery_document) { { "issuer" => issuer, "introspection_endpoint" => endpoint } }
  let(:secret) { described_class::ClientSecret.new("id:value", "test-secret") }
  let(:response) { json_response({ "active" => false }) }
  let(:http) do
    FakeHTTPClient.new do |url|
      case url
      when discovery_url then json_response(discovery_document)
      when endpoint then response
      else raise "unexpected request: #{url}"
      end
    end
  end

  def introspect(zone = issuer, client: http, token: "test-token", credential: secret, **options)
    described_class.introspect_token(zone, token: token, credential: credential, http_client: client, **options)
  end

  it "1: POSTs the token to the discovered endpoint with HTTP Basic authentication" do
    introspect(timeout: 4)

    expect(http.requests).to eq([discovery_url, endpoint])
    expect(http.calls.map(&:timeout)).to eq([4, 4])
    call = http.calls.last
    expect(call.verb).to eq(:post)
    expect(call.params).to eq([%w[token test-token]])
    expect(call.headers.fetch("Authorization")).to eq("Basic #{["id%3Avalue:test-secret"].pack("m0")}")
  end

  it "2: sends credential fields and headers and signs the assertion for the zone issuer" do
    Dir.mktmpdir do |dir|
      signer = described_class::WebIdentity.new(client_id: "web-client", storage_dir: dir)
      credential = Object.new
      credential.define_singleton_method(:client_authentication) do |issuer:, endpoint:|
        auth = signer.client_authentication(issuer: issuer, endpoint: endpoint)
        auth.with(headers: { "X-Test-Credential" => issuer })
      end

      introspect("#{issuer}/", credential: credential)

      call = http.calls.last
      form = call.params.to_h
      expect(call.headers).to include("X-Test-Credential" => issuer)
      expect(form).to include("client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      expect(form.keys).to contain_exactly("token", "client_assertion", "client_assertion_type")
      key = JWT::JWK.import(signer.public_jwks.fetch("keys").first).verify_key
      claims, = JWT.decode(form.fetch("client_assertion"), key, true, algorithm: "RS256")
      expect(claims.fetch("aud")).to eq(issuer)
    end
  end

  it "3: exposes the standard access token claims and splits the wire scope" do
    claims = { active: true, token_type: "Bearer", iss: issuer, sub: "user-1", client_id: "client-1",
               aud: %w[resource-1 resource-2], scope: "read write", sid: "session-1", jti: "token-1",
               iat: 1_731_000_000, exp: 1_731_003_600 }
    client = FakeHTTPClient.new { json_response(claims) }

    result = introspect(nil, client: client, metadata: metadata)

    expect(result).to be_a(described_class::TokenIntrospection)
    expect(result).to have_attributes(**claims, scope: %w[read write])
  end

  it "4: returns an inactive result without claims or an error" do
    result = introspect

    expect(result).to have_attributes(active: false, token_type: nil, scope: nil, raw: { "active" => false })
  end

  it "5: requires the advertised introspection endpoint without guessing a path" do
    client = FakeHTTPClient.new { json_response({ "issuer" => issuer }) }

    expect { introspect(client: client) }.to raise_error(described_class::ConfigurationError, /introspection_endpoint/)
    expect(client.requests).to eq([discovery_url])
  end

  it "6: preserves authorization-server errors, status, and retryability" do
    [[401, "invalid_client", false], [400, "invalid_request", true]].each do |status, code, retryable|
      client = FakeHTTPClient.new do
        json_response({ "error" => code, "error_description" => "server detail" }, status: status)
      end

      expect { introspect(nil, client: client, metadata: metadata) }
        .to raise_error(described_class::OAuthError) do |error|
          expect(error).to have_attributes(error: code, error_description: "server detail",
                                           status: status, retryable?: retryable)
        end
    end
  end

  it "7: returns retryable errors for transport failures and 5xx responses without retrying" do
    network_error = described_class::NetworkError
    failures = [
      [-> { raise network_error, "connection refused" }, network_error],
      [-> { response.with(status: 503, body: "unavailable") }, described_class::HTTPError],
      [-> { json_response({ "error" => "server_error" }, status: 500) }, described_class::OAuthError]
    ]
    failures.each do |handler, error_class|
      client = FakeHTTPClient.new { handler.call }

      expect { introspect(nil, client: client, metadata: metadata) }.to raise_error(error_class) do |error|
        expect(error).to be_retryable
      end
      expect(client.requests).to eq([endpoint])
    end
  end

  it "8: rejects empty, malformed, and invalid JSON responses with invalid_response" do
    ["", "not JSON", "[]", "{}", '{"active":null}', '{"active":"false"}', '{"active":1}'].each do |body|
      client = FakeHTTPClient.new { response.with(body: body) }

      expect { introspect(nil, client: client, metadata: metadata) }
        .to raise_error(described_class::ProtocolError) do |error|
          expect(error).to have_attributes(code: "invalid_response", retryable?: true)
        end
    end
  end

  it "9: requests a fresh result each time the same token is checked" do
    active = true
    client = FakeHTTPClient.new { json_response({ active: active }) }

    expect(introspect(nil, client: client, metadata: metadata).active).to be(true)
    active = false
    expect(introspect(nil, client: client, metadata: metadata).active).to be(false)
    expect(client.requests).to eq([endpoint, endpoint])
  end

  it "10: uses supplied metadata without discovery" do
    expect(introspect(nil, metadata: metadata).active).to be(false)
    expect(http.requests).to eq([endpoint])
  end

  it "11: rejects a missing or incapable credential before making any request" do
    expect { introspect(credential: nil) }
      .to raise_error(described_class::ConfigurationError, "token introspection requires a credential")
    expect { introspect(credential: Object.new) }
      .to raise_error(described_class::ConfigurationError, /does not provide client authentication/)
    expect(http.requests).to be_empty
  end

  it "12: rejects an empty or missing token before making any request" do
    ["", nil].each do |token|
      expect { introspect(token: token) }.to raise_error(described_class::ConfigurationError, /token/)
    end
    expect(http.requests).to be_empty
  end

  it "13: types the issuer and preserves unknown claims" do
    claims = { "active" => true, "iss" => issuer, "act" => { "sub" => "actor" }, "sub_profile" => "user" }
    client = FakeHTTPClient.new { json_response(claims) }

    result = introspect(nil, client: client, metadata: metadata)

    expect(result.iss).to eq(issuer)
    expect(result["act"]).to eq({ "sub" => "actor" })
    expect(result["sub_profile"]).to eq("user")
    expect(result.raw).to eq(claims)
  end

  it "14: returns an active refresh token without defaulting token_type" do
    client = FakeHTTPClient.new { json_response({ "active" => true, "aud" => issuer, "sid" => "session-1" }) }

    result = introspect(nil, client: client, metadata: metadata)

    expect(result).to have_attributes(active: true, aud: issuer, sid: "session-1", token_type: nil)
    expect(result.raw).not_to have_key("token_type")
  end

  it "15: sends a supplied token type hint unchanged and omits it otherwise" do
    introspect(token_type_hint: "Custom-Hint")
    introspect

    forms = http.calls.select { |call| call.verb == :post }.map { |call| call.params.to_h }
    expect(forms.map { |form| form["token_type_hint"] }).to eq(["Custom-Hint", nil])
    expect(forms.last).not_to have_key("token_type_hint")
  end

  it "does not send credentials to a non-HTTPS endpoint" do
    insecure = metadata.with(introspection_endpoint: "http://zone.test/introspect")

    expect { introspect(nil, metadata: insecure) }.to raise_error(described_class::ConfigurationError, /HTTPS/)
    expect(http.requests).to be_empty
  end

  it "rejects metadata from a different issuer" do
    expect { introspect("https://other.test", metadata: metadata) }
      .to raise_error(described_class::ConfigurationError, /does not match/)
    expect(http.requests).to be_empty
  end

  it "uses the explicit issuer as supplied for credential zone lookup when metadata also matches" do
    expect(secret).to receive(:client_authentication)
      .with(issuer: "#{issuer}/", endpoint: issuer).and_call_original

    introspect("#{issuer}/", metadata: metadata)

    expect(http.requests).to eq([endpoint])
  end

  it "signs for the advertised issuer when the explicit issuer differs by a trailing slash" do
    Dir.mktmpdir do |dir|
      credential = described_class::WebIdentity.new(client_id: "web-client", storage_dir: dir)

      introspect("#{issuer}/", metadata: metadata, credential: credential)

      assertion = http.calls.last.params.to_h.fetch("client_assertion")
      key = JWT::JWK.import(credential.public_jwks.fetch("keys").first).verify_key
      claims, = JWT.decode(assertion, key, true, algorithm: "RS256")
      expect(claims.fetch("aud")).to eq(metadata.issuer)
    end
  end
end
