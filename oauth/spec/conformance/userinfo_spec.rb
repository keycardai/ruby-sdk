# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/oauth-client/userinfo.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe "UserInfo" do
  let(:zone) { ZoneFixture.new }
  let(:claims) { { "sub" => "usr_123", "email" => "ada@acme.test" } }

  # A zone whose discovery document advertises the userinfo_endpoint, with the
  # UserInfo response supplied per example.
  def userinfo_http(response)
    FakeHTTPClient.new do |url, _params|
      url == zone.metadata_url ? json_response(zone.metadata(oidc: true)) : response
    end
  end

  def fetch(http, **options)
    Keycardai::OAuth.fetch_userinfo(zone.issuer, access_token: "at_user", http_client: http, **options)
  end

  def userinfo_call(http)
    http.calls.find { |call| call.url == zone.userinfo_url }
  end

  it "1: returns sub and every claim for a claims document" do
    http = userinfo_http(json_response(claims.merge("groups" => ["engineering"])))

    response = fetch(http)

    expect(response.sub).to eq("usr_123")
    expect(response.claims).to eq(claims.merge("groups" => ["engineering"]))
    expect(userinfo_call(http).headers).to include(
      "Accept" => "application/json",
      "Authorization" => "Bearer at_user"
    )
  end

  it "2: raises a protocol error when the response omits sub" do
    http = userinfo_http(json_response({ "email" => "ada@acme.test" }))

    expect { fetch(http) }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("invalid_response") }
  end

  it "3: surfaces a 401 challenge as a typed error carrying its error code" do
    challenge = 'Bearer realm="acme", error="invalid_token", error_description="expired"'
    http = userinfo_http(
      Keycardai::OAuth::HTTP::Response.new(status: 401, headers: { "WWW-Authenticate" => challenge }, body: "")
    )

    expect { fetch(http) }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.error).to eq("invalid_token")
        expect(e.status).to eq(401)
      }
  end

  it "4: raises a configuration error, before any request, when metadata has no userinfo_endpoint" do
    metadata = Keycardai::OAuth::Discovery.parse_metadata(zone.issuer, JSON.dump(zone.metadata))
    http = zone.http_client

    expect { fetch(http, metadata: metadata) }.to raise_error(Keycardai::OAuth::ConfigurationError)
    expect(http.requests).to be_empty

    # Discovering first is the same failure, with no request past discovery.
    expect { fetch(http) }.to raise_error(Keycardai::OAuth::ConfigurationError)
    expect(http.requests).to eq([zone.metadata_url])
  end

  it "5: rejects an application/jwt response, naming the content type" do
    http = userinfo_http(
      Keycardai::OAuth::HTTP::Response.new(status: 200, headers: { "Content-Type" => "application/jwt" },
                                           body: "header.payload.signature")
    )

    expect { fetch(http) }
      .to raise_error(Keycardai::OAuth::ProtocolError, %r{application/jwt}) { |e|
        expect(e.code).to eq("invalid_response")
      }
  end

  it "6: preserves unknown claims beyond the common set" do
    http = userinfo_http(json_response(claims.merge("acme_tenant" => "t_1")))

    expect(fetch(http)["acme_tenant"]).to eq("t_1")
  end

  it "skips discovery when the caller supplies pre-discovered metadata" do
    metadata = Keycardai::OAuth::Discovery.parse_metadata(zone.issuer, JSON.dump(zone.metadata(oidc: true)))
    http = FakeHTTPClient.new { |_url, _params| json_response(claims) }

    expect(fetch(http, metadata: metadata).sub).to eq("usr_123")
    expect(http.requests).to eq([zone.userinfo_url])
  end

  it "raises an HTTP error for a non-2xx status other than 401" do
    http = userinfo_http(json_response({}, status: 503))

    expect { fetch(http) }
      .to raise_error(Keycardai::OAuth::HTTPError) { |e| expect(e.status).to eq(503) }
  end
end
