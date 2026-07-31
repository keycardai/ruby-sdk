# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/jwt-jwks/jwks-caching.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::JWKSKeyring do
  let(:zone) { ZoneFixture.new }
  let(:clock_time) { { now: Time.now } }
  let(:clock) { -> { clock_time[:now] } }

  def keyring(http_client, **options)
    described_class.new(http_client: http_client, clock: clock, **options)
  end

  it "1: cold cache discovers jwks_uri, fetches JWKS, returns the matching key" do
    http = zone.http_client
    key = keyring(http).key(zone.issuer, "kid-1")

    expect(key.public_to_pem).to eq(zone.private_key.public_key.public_to_pem)
    expect(http.requests).to eq([zone.metadata_url, zone.jwks_url])
  end

  it "2: second lookup of the same (issuer, kid) within key_ttl is served from cache with no network call" do
    http = zone.http_client
    ring = keyring(http)
    ring.key(zone.issuer, "kid-1")

    expect { ring.key(zone.issuer, "kid-1") }.not_to change(http.requests, :size)
  end

  it "3: lookup after key_ttl has elapsed re-fetches the JWKS and returns the key" do
    http = zone.http_client
    ring = keyring(http, key_ttl: 300)
    ring.key(zone.issuer, "kid-1")
    clock_time[:now] += 301

    key = ring.key(zone.issuer, "kid-1")

    expect(key).not_to be_nil
    expect(http.request_count(zone.jwks_url)).to eq(2)
  end

  it "4: a different kid on the same issuer reuses the cached jwks_uri without re-discovery" do
    zone = ZoneFixture.new(kids: %w[kid-1 kid-2])
    http = zone.http_client
    ring = keyring(http)
    ring.key(zone.issuer, "kid-1")

    ring.key(zone.issuer, "kid-2")

    expect(http.request_count(zone.metadata_url)).to eq(1)
    expect(http.request_count(zone.jwks_url)).to eq(2)
  end

  it "5: a kid absent from the fetched JWKS raises a key-not-found error" do
    expect { keyring(zone.http_client).key(zone.issuer, "missing-kid") }
      .to raise_error(Keycardai::OAuth::JWKSKeyNotFoundError)
  end

  it "6: discovery returning no jwks_uri raises a discovery error" do
    http = zone.http_client(zone.metadata_url => -> { json_response({ "issuer" => zone.issuer }) })

    expect { keyring(http).key(zone.issuer, "kid-1") }
      .to raise_error(Keycardai::OAuth::JWKSDiscoveryError)
  end

  it "7: a non-2xx JWKS endpoint raises a fetch error" do
    http = zone.http_client(zone.jwks_url => -> { json_response({}, status: 503) })

    expect { keyring(http).key(zone.issuer, "kid-1") }
      .to raise_error(Keycardai::OAuth::JWKSFetchError)
  end

  it "8: a cross-origin jwks_uri is rejected before fetching keys" do
    http = zone.http_client(
      zone.metadata_url => -> { json_response(zone.metadata(jwks_uri: "https://evil.test/jwks.json")) }
    )

    expect { keyring(http).key(zone.issuer, "kid-1") }
      .to raise_error(Keycardai::OAuth::JWKSUriValidationError)
    expect(http.requests).to eq([zone.metadata_url])
  end

  it "9: concurrent cold-cache lookups for the same (issuer, kid) trigger a single JWKS fetch" do
    http = FakeHTTPClient.new do |url|
      sleep 0.05
      url == zone.metadata_url ? json_response(zone.metadata) : json_response(zone.jwks)
    end
    ring = keyring(http)

    keys = Array.new(4) { Thread.new { ring.key(zone.issuer, "kid-1") } }.map(&:value)

    expect(keys.uniq.size).to eq(1)
    expect(http.request_count(zone.metadata_url)).to eq(1)
    expect(http.request_count(zone.jwks_url)).to eq(1)
  end

  describe "bounded cache" do
    it "evicts the oldest entry on overflow instead of growing unbounded" do
      zone = ZoneFixture.new(kids: (1..3).map { |i| "kid-#{i}" })
      http = zone.http_client
      ring = keyring(http)
      stub_const("#{described_class}::MAX_CACHED_KEYS", 2)

      ring.key(zone.issuer, "kid-1")
      ring.key(zone.issuer, "kid-2")
      ring.key(zone.issuer, "kid-3")
      ring.key(zone.issuer, "kid-1")

      expect(http.request_count(zone.jwks_url)).to eq(4)
    end
  end

  describe "#invalidate" do
    it "drops cached keys and discovery so the next lookup re-resolves" do
      http = zone.http_client
      ring = keyring(http)
      ring.key(zone.issuer, "kid-1")

      ring.invalidate
      ring.key(zone.issuer, "kid-1")

      expect(http.request_count(zone.metadata_url)).to eq(2)
      expect(http.request_count(zone.jwks_url)).to eq(2)
    end
  end
end
