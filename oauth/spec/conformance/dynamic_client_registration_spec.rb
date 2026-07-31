# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/oauth-client/dynamic-client-registration.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe "Dynamic client registration" do
  let(:zone) { ZoneFixture.new }
  let(:registration_payload) do
    { "client_id" => "client_new", "client_secret" => "secret_new", "client_id_issued_at" => 1_753_920_000,
      "client_secret_expires_at" => 0, "registration_access_token" => "rat_abc",
      "registration_client_uri" => "#{zone.issuer}/oauth/register/client_new", "client_name" => "My Tool" }
  end

  def registration_http(payload = registration_payload, status: 200)
    FakeHTTPClient.new do |url, _body|
      url == zone.metadata_url ? json_response(zone.metadata) : json_response(payload, status: status)
    end
  end

  def register(http, **options)
    Keycardai::OAuth.register_client(zone.issuer, http_client: http, **options)
  end

  def registration_call(http)
    http.calls.find { |call| call.url == zone.registration_url }
  end

  it "1: sends named fields and additional_metadata, with named fields winning on conflict" do
    http = registration_http
    register(
      http,
      client_name: "My Tool",
      grant_types: ["authorization_code"],
      token_endpoint_auth_method: "none",
      additional_metadata: { "client_name" => "overridden loser", "x_vendor" => "kept" }
    )

    call = registration_call(http)
    expect(call.verb).to eq(:post_json)
    expect(call.params).to include(
      "client_name" => "My Tool",
      "grant_types" => ["authorization_code"],
      "token_endpoint_auth_method" => "none",
      "x_vendor" => "kept"
    )
    expect(call.params).not_to have_key("redirect_uris")
  end

  it "2: parses a 2xx registration response" do
    response = register(registration_http, client_name: "My Tool")

    expect(response).to have_attributes(
      client_id: "client_new",
      client_secret: "secret_new",
      client_id_issued_at: 1_753_920_000,
      client_secret_expires_at: 0,
      registration_access_token: "rat_abc",
      registration_client_uri: "#{zone.issuer}/oauth/register/client_new"
    )
    expect(response["client_name"]).to eq("My Tool")
  end

  it "3: rejects a response missing client_id" do
    http = registration_http({ "client_name" => "My Tool" })

    expect { register(http, client_name: "My Tool") }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("invalid_response") }
  end

  it "4: surfaces an OAuth error response as a typed error with its fields" do
    http = registration_http({ "error" => "invalid_client_metadata", "error_description" => "bad redirect" },
                             status: 400)

    expect { register(http, client_name: "My Tool") }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.error).to eq("invalid_client_metadata")
        expect(e.error_description).to eq("bad redirect")
      }
  end

  it "authenticates the registration with an initial access token when given" do
    http = registration_http
    register(http, client_name: "My Tool", initial_access_token: "iat_123")

    expect(registration_call(http).headers["Authorization"]).to eq("Bearer iat_123")
  end
end
