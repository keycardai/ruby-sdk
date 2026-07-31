# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/oauth-client/authorization-server-discovery.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe "Authorization server discovery" do
  let(:zone) { ZoneFixture.new }

  def discover(http)
    Keycardai::OAuth.fetch_authorization_server_metadata(zone.issuer, http_client: http)
  end

  it "1: returns metadata with issuer and endpoint fields for a well-formed document" do
    metadata = discover(zone.http_client)

    expect(metadata.issuer).to eq(zone.issuer)
    expect(metadata.token_endpoint).to eq(zone.token_url)
    expect(metadata.jwks_uri).to eq(zone.jwks_url)
    expect(metadata.authorization_endpoint).to eq("#{zone.issuer}/oauth/authorize")
  end

  it "2: succeeds when the response issuer matches the request, ignoring a trailing slash" do
    http = zone.http_client(zone.metadata_url => lambda {
      json_response(zone.metadata.merge("issuer" => "#{zone.issuer}/"))
    })

    expect(discover(http).issuer).to eq("#{zone.issuer}/")
  end

  it "3: raises issuer_mismatch when the response issuer differs from the request" do
    http = zone.http_client(zone.metadata_url => lambda {
      json_response(zone.metadata.merge("issuer" => "https://evil.test"))
    })

    expect { discover(http) }.to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("issuer_mismatch") }
  end

  it "4: raises an HTTP error on a non-2xx response" do
    http = zone.http_client(zone.metadata_url => -> { json_response({}, status: 500) })

    expect { discover(http) }.to raise_error(Keycardai::OAuth::HTTPError) { |e| expect(e.status).to eq(500) }
  end

  it "5: raises a typed protocol error on malformed JSON or a missing issuer" do
    malformed = zone.http_client(
      zone.metadata_url => -> { Keycardai::OAuth::HTTP::Response.new(status: 200, headers: {}, body: "not json") }
    )
    missing_issuer = zone.http_client(zone.metadata_url => -> { json_response({ "token_endpoint" => zone.token_url }) })

    expect { discover(malformed) }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("invalid_metadata") }
    expect { discover(missing_issuer) }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("invalid_metadata") }
  end

  it "6: preserves unknown fields beyond the standard set" do
    http = zone.http_client(zone.metadata_url => -> { json_response(zone.metadata.merge("x_vendor_field" => "kept")) })

    expect(discover(http)["x_vendor_field"]).to eq("kept")
  end

  it "raises a configuration error for an empty issuer" do
    expect { Keycardai::OAuth.fetch_authorization_server_metadata("", http_client: zone.http_client) }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end
end
