# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/oauth-client/token-exchange.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::TokenExchangeClient do
  let(:zone) { ZoneFixture.new }
  let(:token_payload) do
    { "access_token" => "at_new", "token_type" => "Bearer", "expires_in" => 300,
      "scope" => "read write", "issued_token_type" => Keycardai::OAuth::TokenType::ACCESS_TOKEN }
  end

  def token_http(payload = token_payload, status: 200)
    FakeHTTPClient.new do |url, _params|
      url == zone.metadata_url ? json_response(zone.metadata) : json_response(payload, status: status)
    end
  end

  def client(http, **options)
    described_class.new(issuer: zone.issuer, http_client: http, **options)
  end

  def token_call(http)
    http.calls.find { |call| call.url == zone.token_url }
  end

  it "1: defaults grant_type to token-exchange and subject_token_type to access-token" do
    http = token_http
    client(http).exchange_token(subject_token: "at_subject")

    expect(token_call(http).params).to include(
      "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
      "subject_token" => "at_subject",
      "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token"
    )
  end

  it "2: form-encodes resource, scope, and actor_token/actor_token_type when set" do
    http = token_http
    client(http).exchange_token(
      subject_token: "at_subject", resource: "https://api.acme.test", scope: "read",
      actor_token: "at_actor", actor_token_type: Keycardai::OAuth::TokenType::ACCESS_TOKEN
    )

    expect(token_call(http).params).to include(
      "resource" => "https://api.acme.test",
      "scope" => "read",
      "actor_token" => "at_actor",
      "actor_token_type" => "urn:ietf:params:oauth:token-type:access_token"
    )
  end

  it "3: a shared-secret client sends an HTTP Basic Authorization header" do
    http = token_http
    client(http, client_id: "cid", client_secret: "csecret").exchange_token(subject_token: "at_subject")

    expect(token_call(http).headers["Authorization"]).to eq("Basic #{["cid:csecret"].pack("m0")}")
  end

  it "4: client_assertion fields are form-encoded with no Basic header when no secret is configured" do
    http = token_http
    client(http).exchange_token(
      subject_token: "at_subject",
      client_assertion: "assertion-jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )

    call = token_call(http)
    expect(call.params).to include(
      "client_assertion" => "assertion-jwt",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    expect(call.headers).not_to have_key("Authorization")
  end

  it "5: parses a 2xx response into the token result" do
    response = client(token_http).exchange_token(subject_token: "at_subject")

    expect(response).to have_attributes(
      access_token: "at_new", token_type: "Bearer", expires_in: 300,
      scope: %w[read write], issued_token_type: Keycardai::OAuth::TokenType::ACCESS_TOKEN
    )
  end

  it "6: surfaces an OAuth error response as a typed error with its fields" do
    http = token_http({ "error" => "invalid_target", "error_description" => "unknown resource" }, status: 400)

    expect { client(http).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.error).to eq("invalid_target")
        expect(e.error_description).to eq("unknown resource")
        expect(e.status).to eq(400)
      }
  end

  it "7: rejects a token response missing access_token" do
    http = token_http({ "token_type" => "Bearer" })

    expect { client(http).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("invalid_response") }
  end

  it "discovers the token endpoint once and caches it across calls" do
    http = token_http
    exchange = client(http)
    exchange.exchange_token(subject_token: "at_1")
    exchange.exchange_token(subject_token: "at_2")

    expect(http.request_count(zone.metadata_url)).to eq(1)
    expect(http.request_count(zone.token_url)).to eq(2)
  end

  it "requires actor_token_type when actor_token is set" do
    expect { client(token_http).exchange_token(subject_token: "at", actor_token: "at_actor") }
      .to raise_error(ArgumentError, /actor_token_type/)
  end

  it "requires client_id and client_secret together" do
    expect { client(token_http, client_id: "cid") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end
end
