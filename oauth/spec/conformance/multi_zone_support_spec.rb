# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/multi-zone-and-ops/multi-zone-support.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe "Multi-zone support" do
  let(:zone_a) { ZoneFixture.new(issuer: "https://acme.test") }
  let(:zone_b) { ZoneFixture.new(issuer: "https://beta.test") }

  let(:credential) do
    Keycardai::OAuth::ClientSecret.new(
      zone_a.issuer => %w[cid_a secret_a],
      zone_b.issuer => %w[cid_b secret_b]
    )
  end

  # One transport serving both zones' metadata, JWKS, and token endpoints.
  def two_zone_http
    routes = {
      zone_a.metadata_url => -> { json_response(zone_a.metadata) },
      zone_b.metadata_url => -> { json_response(zone_b.metadata) },
      zone_a.jwks_url => -> { json_response(zone_a.jwks) },
      zone_b.jwks_url => -> { json_response(zone_b.jwks) }
    }
    FakeHTTPClient.new do |url, _params|
      handler = routes[url]
      handler ? handler.call : json_response({ "access_token" => "at" })
    end
  end

  def verifier(http)
    Keycardai::OAuth::TokenVerifier.new(issuers: [zone_a.issuer, zone_b.issuer], http_client: http)
  end

  it "1: a two-zone credential is self-describing and resolves per-zone credentials" do
    expect(credential.multi_zone?).to be(true)
    expect(credential.authorization_header(issuer: zone_a.issuer)).to eq("Basic #{["cid_a:secret_a"].pack("m0")}")
    expect(credential.authorization_header(issuer: zone_b.issuer)).to eq("Basic #{["cid_b:secret_b"].pack("m0")}")
  end

  it "2: an inbound zone A token verifies against zone A's issuer; zone B's keys are never fetched" do
    http = two_zone_http
    access_token = verifier(http).verify_token_for_zone(zone_a.token, zone_a.issuer)

    expect(access_token.issuer).to eq(zone_a.issuer)
    expect(http.request_count(zone_b.jwks_url)).to eq(0)

    expect { verifier(two_zone_http).verify_token_for_zone(zone_b.token, zone_a.issuer) }
      .to raise_error(Keycardai::OAuth::InvalidTokenError)
  end

  it "3: an outbound exchange resolved to zone A uses zone A's credential and targets zone A" do
    http = two_zone_http
    client = Keycardai::OAuth::TokenExchangeClient.new(
      issuer: zone_a.issuer, credential: credential, http_client: http
    )

    client.exchange_token(subject_token: "at_subject", issuer: zone_a.issuer)

    call = http.calls.find { |c| c.url == zone_a.token_url }
    expect(call.headers["Authorization"]).to eq("Basic #{["cid_a:secret_a"].pack("m0")}")
    expect(http.calls.map(&:url)).not_to include(zone_b.token_url)
  end

  it "4: a token for an unresolvable zone is rejected fail-closed" do
    intruder = ZoneFixture.new(issuer: "https://intruder.test")

    expect { verifier(two_zone_http).verify_token(intruder.token) }
      .to raise_error(Keycardai::OAuth::InvalidTokenError)
    expect { verifier(two_zone_http).verify_token_for_zone(zone_a.token, "https://intruder.test") }
      .to raise_error(Keycardai::OAuth::InvalidTokenError)
  end

  it "5: an exchange resolved to a zone with no configured credential fails closed" do
    http = two_zone_http
    partial = Keycardai::OAuth::ClientSecret.new(zone_a.issuer => %w[cid_a secret_a])
    client = Keycardai::OAuth::TokenExchangeClient.new(
      issuer: zone_a.issuer, credential: partial, http_client: http
    )

    expect { client.exchange_token(subject_token: "at", issuer: zone_b.issuer) }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
    expect(http.calls.map(&:url)).not_to include(zone_b.token_url)
  end

  it "6: interleaved requests for two zones are served from zone-scoped caches" do
    http = two_zone_http
    shared_verifier = verifier(http)

    2.times do
      shared_verifier.verify_token_for_zone(zone_a.token, zone_a.issuer)
      shared_verifier.verify_token_for_zone(zone_b.token, zone_b.issuer)
    end

    expect(http.request_count(zone_a.jwks_url)).to eq(1)
    expect(http.request_count(zone_b.jwks_url)).to eq(1)
    expect(http.request_count(zone_a.metadata_url)).to eq(1)
    expect(http.request_count(zone_b.metadata_url)).to eq(1)
  end
end
