# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/delegated-access/impersonation.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe "Impersonation" do
  let(:zone) { ZoneFixture.new }
  let(:token_payload) { { "access_token" => "at_impersonated", "token_type" => "Bearer" } }

  def token_http(payload = token_payload, status: 200)
    FakeHTTPClient.new do |url, _params|
      url == zone.metadata_url ? json_response(zone.metadata) : json_response(payload, status: status)
    end
  end

  def client(http)
    Keycardai::OAuth::TokenExchangeClient.new(
      issuer: zone.issuer, client_id: "cid", client_secret: "csecret", http_client: http
    )
  end

  def token_call(http)
    http.calls.find { |call| call.url == zone.token_url }
  end

  it "1: sends a substitute-user subject token naming the user, with no actor_token fields" do
    http = token_http
    response = client(http).impersonate(user_identifier: "usr_123", resource: "https://api.acme.test")

    params = token_call(http).params
    expect(params).to include(
      "subject_token_type" => "urn:keycard:params:oauth:token-type:substitute-user",
      "resource" => "https://api.acme.test"
    )
    expect(params).not_to have_key("actor_token")
    expect(params).not_to have_key("actor_token_type")

    subject_token = params.fetch("subject_token")
    expect(subject_token).to end_with(".")
    header, payload = subject_token.split(".").first(2).map { |part| decode_jwt_part(part) }
    expect(header).to eq("typ" => "vnd.kc.su+jwt", "alg" => "none")
    expect(payload).to eq("sub" => "usr_123")
    expect(response.access_token).to eq("at_impersonated")
  end

  it "2: an unknown user_identifier surfaces invalid_grant" do
    http = token_http({ "error" => "invalid_grant" }, status: 400)

    expect { client(http).impersonate(user_identifier: "usr_unknown", resource: "https://api.acme.test") }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e| expect(e.error).to eq("invalid_grant") }
  end

  it "3: a client without impersonation permission surfaces unauthorized_client" do
    http = token_http({ "error" => "unauthorized_client" }, status: 400)

    expect { client(http).impersonate(user_identifier: "usr_123", resource: "https://api.acme.test") }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e| expect(e.error).to eq("unauthorized_client") }
  end

  it "4: omitting resource is a client-side validation error" do
    expect { client(token_http).impersonate(user_identifier: "usr_123", resource: "") }
      .to raise_error(ArgumentError, /resource/)
    expect { client(token_http).impersonate(user_identifier: "usr_123") }
      .to raise_error(ArgumentError)
  end

  it "5: omitting scope sends no scope field, leaving server-default scopes" do
    http = token_http
    response = client(http).impersonate(user_identifier: "usr_123", resource: "https://api.acme.test")

    expect(token_call(http).params).not_to have_key("scope")
    expect(response.access_token).to eq("at_impersonated")
  end
end
