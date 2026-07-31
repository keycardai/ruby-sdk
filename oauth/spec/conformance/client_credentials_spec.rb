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
end
