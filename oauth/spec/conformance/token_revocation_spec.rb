# frozen_string_literal: true

require "tmpdir"

# Conformance suite for keycard-sdk-spec specs/oauth-client/token-revocation.md.
RSpec.describe Keycardai::OAuth do
  let(:issuer) { "https://zone.test" }
  let(:discovery_url) { "#{issuer}/.well-known/oauth-authorization-server" }
  let(:endpoint) { "#{issuer}/custom/revoke" }
  let(:document) { { "issuer" => issuer, "revocation_endpoint" => endpoint } }
  let(:response) { described_class::HTTP::Response.new(status: 200, headers: {}, body: "") }
  let(:http) do
    FakeHTTPClient.new do |url|
      case url
      when discovery_url then json_response(document)
      when endpoint then response
      else raise "unexpected request: #{url}"
      end
    end
  end

  def revoke(zone = issuer, client: http, **options)
    described_class.revoke_token(zone, token: "refresh-token", client_id: "public-id", **options, http_client: client)
  end

  it "1: POSTs the token, client_id and default hint to the discovered endpoint without Basic auth" do
    revoke(timeout: 4)

    expect(http.requests).to eq([discovery_url, endpoint])
    expect(http.calls.map(&:timeout)).to eq([4, 4])
    call = http.calls.last
    expect(call.verb).to eq(:post)
    expect(call.params).to contain_exactly(%w[token refresh-token], %w[token_type_hint refresh_token],
                                           %w[client_id public-id])
    expect(call.headers).not_to have_key("Authorization")
  end

  it "2: authenticates a client secret with HTTP Basic and omits client_id from the form" do
    revoke(client_id: "id:value", client_secret: "test-secret")

    call = http.calls.last
    expect(call.headers.fetch("Authorization")).to eq("Basic #{["id%3Avalue:test-secret"].pack("m0")}")
    expect(call.params).to contain_exactly(%w[token refresh-token], %w[token_type_hint refresh_token])
  end

  it "3: adds credential headers and form fields and signs the assertion for the issuer" do
    Dir.mktmpdir do |dir|
      signer = described_class::WebIdentity.new(client_id: "web-client", storage_dir: dir)
      credential = Object.new
      credential.define_singleton_method(:client_authentication) do |issuer:, endpoint:|
        auth = signer.client_authentication(issuer: issuer, endpoint: endpoint)
        auth.with(headers: { "X-Test-Credential" => issuer })
      end

      revoke(client_id: nil, credential: credential)

      call = http.calls.last
      form = call.params.to_h
      expect(call.headers).to include("X-Test-Credential" => issuer)
      expect(form).to include("client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      expect(form.keys).to contain_exactly("token", "token_type_hint", "client_assertion", "client_assertion_type")
      key = JWT::JWK.import(signer.public_jwks.fetch("keys").first).verify_key
      claims, = JWT.decode(form.fetch("client_assertion"), key, true, algorithm: "RS256")
      expect(claims.fetch("aud")).to eq(issuer)
    end
  end

  it "4: sends an explicit token type hint unchanged" do
    revoke(token_type_hint: "custom_token_hint")

    expect(http.calls.last.params.to_h.fetch("token_type_hint")).to eq("custom_token_hint")
  end

  it "5: accepts HTTP 200 without parsing a body for known or unknown tokens" do
    non_json = FakeHTTPClient.new do |url|
      url == discovery_url ? json_response(document) : response.with(body: "not JSON")
    end

    expect(revoke).to be_nil
    expect(revoke(token: "unknown-token")).to be_nil
    expect(revoke(client: non_json)).to be_nil
  end

  it "6: requires the advertised revocation endpoint without falling back to a path" do
    client = FakeHTTPClient.new { json_response({ "issuer" => issuer }) }

    expect { revoke(client: client) }.to raise_error(described_class::ConfigurationError) do |error|
      expect(error).not_to be_retryable
    end
    expect(client.requests).to eq([discovery_url])
  end

  it "7: preserves OAuth error data and classifies status before the OAuth code" do
    [[401, "invalid_client", false], [400, "invalid_grant", true], [400, "unsupported_token_type", true],
     [429, "invalid_client", true], [503, "invalid_client", true]].each do |status, code, retryable|
      client = FakeHTTPClient.new do |url|
        if url == discovery_url
          json_response(document)
        else
          json_response({ "error" => code, "error_description" => "server detail", "reason" => "zone_reason" },
                        status: status)
        end
      end

      expect { revoke(client: client) }.to raise_error(described_class::OAuthError) do |error|
        expect(error).to have_attributes(error: code, error_description: "server detail", reason: "zone_reason",
                                         status: status, retryable?: retryable)
      end
      expect(client.requests).to eq([discovery_url, endpoint])
    end
  end

  it "8: classifies transport failures and plain 5xx responses as retryable without retrying" do
    [nil, 503, 429, 400].each do |status|
      client = FakeHTTPClient.new do |url|
        next json_response(document) if url == discovery_url
        raise described_class::NetworkError, "connection refused" if status.nil?

        response.with(status: status, body: "plain response")
      end
      error_class = status ? described_class::HTTPError : described_class::NetworkError

      expect { revoke(client: client) }.to raise_error(error_class) do |error|
        expect(error.retryable?).to eq(status != 400)
      end
      expect(client.requests).to eq([discovery_url, endpoint])
    end
  end

  it "9: rejects mutually exclusive or incapable credentials before any request" do
    credential = described_class::ClientSecret.new("client-id", "client-secret")
    [{ credential: credential }, { credential: credential, client_id: nil, client_secret: "secret" },
     { credential: Object.new, client_id: nil }, { client_id: nil }].each do |options|
      expect { revoke(**options) }.to raise_error(described_class::ConfigurationError)
    end
    expect(http.requests).to be_empty
  end

  it "10: uses pre-discovered metadata without making a discovery request" do
    metadata = described_class::AuthorizationServerMetadata.new(issuer: issuer, revocation_endpoint: endpoint)

    expect(revoke(nil, metadata: metadata)).to be_nil
    expect(http.requests).to eq([endpoint])
  end

  it "11: rejects empty or missing tokens without making a request" do
    expect { revoke(token: "") }.to raise_error(described_class::ConfigurationError)
    expect { described_class.revoke_token(issuer, client_id: "public-id", http_client: http) }
      .to raise_error(described_class::ConfigurationError)
    expect(http.requests).to be_empty
  end

  it "12: classifies invalid_grant and unsupported_token_type according to the base retry table" do
    %w[invalid_grant unsupported_token_type].each do |code|
      expect { revoke(client: oauth_error_client(code)) }.to raise_error(described_class::OAuthError) do |error|
        expect(error).to be_retryable
      end
    end
  end

  it "13: surfaces unsupported_token_type for an exchanged access token with act" do
    expect_unsupported_token_type(unsigned_token({ "iss" => issuer, "sid" => "s-1", "act" => { "sub" => "agent" } }))
  end

  it "14: surfaces unsupported_token_type for an access token without sid" do
    expect_unsupported_token_type(unsigned_token({ "iss" => issuer }))
  end

  it "15: surfaces unsupported_token_type for a recognized JWT type from another issuer" do
    expect_unsupported_token_type(unsigned_token({ "iss" => "https://other.test", "sid" => "s-1" }))
  end

  it "compares supplied metadata and explicit issuers, preserving the explicit issuer for authentication" do
    metadata = described_class::AuthorizationServerMetadata.new(issuer: issuer, revocation_endpoint: endpoint)
    credential = Object.new
    credential.define_singleton_method(:client_authentication) do |issuer:, endpoint:|
      Keycardai::OAuth::ClientAuthentication.new(headers: { "X-Issuer" => issuer, "X-Audience" => endpoint })
    end

    expect { revoke("https://other.test", metadata: metadata) }.to raise_error(described_class::ConfigurationError)
    expect(http.requests).to be_empty
    revoke("#{issuer}/", metadata: metadata, client_id: nil, credential: credential)
    expect(http.calls.last.headers).to include("X-Issuer" => "#{issuer}/", "X-Audience" => "#{issuer}/")
    expect(http.requests).to eq([endpoint])
  end

  it "rejects insecure or malformed revocation endpoints without sending credentials" do
    ["http://zone.test/revoke", "/revoke", "https://"].each do |url|
      metadata = described_class::AuthorizationServerMetadata.new(issuer: issuer, revocation_endpoint: url)

      expect { revoke(metadata: metadata) }.to raise_error(described_class::ConfigurationError)
    end
    expect(http.requests).to be_empty
  end

  def oauth_error_client(code)
    FakeHTTPClient.new do |url|
      url == discovery_url ? json_response(document) : json_response({ "error" => code }, status: 400)
    end
  end

  def unsigned_token(claims)
    JWT.encode(claims, nil, "none", { "typ" => "at+jwt" })
  end

  def expect_unsupported_token_type(token)
    client = oauth_error_client("unsupported_token_type")
    expect { revoke(client: client, token: token) }.to raise_error(described_class::OAuthError) do |error|
      expect(error).to have_attributes(status: 400, error: "unsupported_token_type")
    end
    expect(client.calls.last.params.to_h.fetch("token")).to eq(token)
  end
end
