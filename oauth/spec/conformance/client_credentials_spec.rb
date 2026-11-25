# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/oauth-client/client-credentials.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::ClientCredentialsClient do
  let(:zone) { ZoneFixture.new }
  let(:token_payload) do
    { "access_token" => "at_workload", "token_type" => "Bearer", "expires_in" => 600, "scope" => "read" }
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

  def request(subject)
    subject.request_token(scope: "read")
  end

  include_examples "token-endpoint discovery is not sticky", %w[7 8 9 10 11 12]

  it "1: a request with a scope sets grant_type=client_credentials and scope in the body" do
    http = token_http
    client(http).request_token(scope: "read")

    expect(token_call(http).params).to include("grant_type" => "client_credentials", "scope" => "read")
  end

  it "2: a resource is form-encoded in the body" do
    http = token_http
    client(http).request_token(resource: "https://api.acme.test")

    expect(token_call(http).params).to include("resource" => "https://api.acme.test")
  end

  it "3: a shared-secret client sends an HTTP Basic Authorization header" do
    http = token_http
    client(http, client_id: "cid", client_secret: "csecret").request_token

    expect(token_call(http).headers["Authorization"]).to eq("Basic #{["cid:csecret"].pack("m0")}")
  end

  it "4: client_assertion and client_assertion_type are form-encoded in the body" do
    http = token_http
    client(http).request_token(
      client_assertion: "assertion-jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )

    expect(token_call(http).params).to include(
      "client_assertion" => "assertion-jwt",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
  end

  it "4a: client_assertion, client_assertion_type, and client_id are form-encoded with no Basic header" do
    http = token_http
    client(http).request_token(
      client_assertion: "assertion-jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_id: "app_123"
    )

    call = token_call(http)
    expect(call.params).to include(
      "client_assertion" => "assertion-jwt",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_id" => "app_123"
    )
    expect(call.headers).not_to have_key("Authorization")
  end

  it "rejects a body client_id on a Basic-authenticated client before any request" do
    http = token_http

    expect { client(http, client_id: "cid", client_secret: "csecret").request_token(client_id: "app_123") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
    expect(http.calls).to be_empty
  end

  it "accepts a body client_id on a client whose credential sends no Basic header" do
    http = token_http
    credential = Keycardai::OAuth::WorkloadIdentity.new(source: -> { "platform-token" })

    client(http, credential: credential).request_token(client_assertion: "platform-token", client_id: "app_123")

    call = token_call(http)
    expect(call.params).to include("client_id" => "app_123")
    expect(call.headers).not_to have_key("Authorization")
  end

  it "5: parses a 2xx token response" do
    response = client(token_http).request_token

    expect(response).to have_attributes(
      access_token: "at_workload", token_type: "Bearer", expires_in: 600, scope: %w[read]
    )
  end

  it "6: surfaces an OAuth error response as a typed error with its fields" do
    http = token_http({ "error" => "invalid_client", "error_description" => "bad secret" }, status: 401)

    expect { client(http).request_token }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.error).to eq("invalid_client")
        expect(e.error_description).to eq("bad secret")
      }
  end

  it "6a: an OAuth error exposes reason and error_description unchanged" do
    http = token_http({ "error" => "access_denied", "error_description" => "Denied", "reason" => "custom_denial" },
                      status: 400)

    expect { client(http).request_token }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.error).to eq("access_denied")
        expect(e.reason).to eq("custom_denial")
        expect(e.error_description).to eq("Denied")
      }
  end

  it "6b: reason is nil when the error response omits it" do
    http = token_http({ "error" => "access_denied", "error_description" => "Denied" }, status: 400)

    expect { client(http).request_token }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.reason).to be_nil
        expect(e.error_description).to eq("Denied")
      }
  end
end
