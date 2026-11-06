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
    expect(http.request_count(zone.jwks_url)).to eq(1)
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

  # Rows 14 to 19 (SDK-93): the per-jwks_uri key set and the refetch cooldown.
  it "14: distinct unknown kids within the cooldown cause one JWKS fetch" do
    http = zone.http_client
    ring = keyring(http)
    ring.key(zone.issuer, "kid-1")

    5.times do |i|
      expect { ring.key(zone.issuer, "forged-#{i}") }.to raise_error(Keycardai::OAuth::JWKSKeyNotFoundError)
    end

    expect(http.request_count(zone.jwks_url)).to eq(1)
  end

  it "15: a kid present in the cached key set imports with no fetch" do
    zone = ZoneFixture.new(kids: %w[kid-1 kid-2])
    http = zone.http_client
    ring = keyring(http)
    ring.key(zone.issuer, "kid-1")

    expect { ring.key(zone.issuer, "kid-2") }.not_to change(http.requests, :size)
  end

  it "16: a rotated-in kid is found once the cooldown has passed" do
    rotated = ZoneFixture.new(issuer: zone.issuer, kids: %w[kid-1 kid-2])
    current = { zone: zone }
    http = zone.http_client(zone.jwks_url => -> { json_response(current[:zone].jwks) })
    ring = keyring(http, refetch_cooldown: 30)
    ring.key(zone.issuer, "kid-1")
    current[:zone] = rotated

    expect { ring.key(zone.issuer, "kid-2") }.to raise_error(Keycardai::OAuth::JWKSKeyNotFoundError)
    clock_time[:now] += 31
    expect(ring.key(zone.issuer, "kid-2")).not_to be_nil
    expect(http.request_count(zone.jwks_url)).to eq(2)
  end

  it "17: concurrent misses for different kids share one JWKS fetch" do
    zone = ZoneFixture.new(kids: %w[a b c d])
    http = zone.http_client
    ring = keyring(http)
    ring.send(:resolve_jwks_uri, zone.issuer)

    threads = %w[a b c d].map { |kid| Thread.new { ring.key(zone.issuer, kid) } }
    threads.each(&:join)

    expect(http.request_count(zone.jwks_url)).to eq(1)
  end

  it "18: invalidate drops the cached key set so the next miss fetches" do
    http = zone.http_client
    ring = keyring(http)
    ring.key(zone.issuer, "kid-1")
    ring.invalidate(zone.issuer)

    expect { ring.key(zone.issuer, "missing") }.to raise_error(Keycardai::OAuth::JWKSKeyNotFoundError)
    expect(http.request_count(zone.jwks_url)).to eq(2)
  end

  it "19: refetch_cooldown 0 fetches on every miss" do
    http = zone.http_client
    ring = keyring(http, refetch_cooldown: 0)
    ring.key(zone.issuer, "kid-1")

    3.times do
      expect { ring.key(zone.issuer, "forged") }.to raise_error(Keycardai::OAuth::JWKSKeyNotFoundError)
    end

    expect(http.request_count(zone.jwks_url)).to eq(4)
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

      expect(ring.instance_variable_get(:@keys).size).to be <= 2
      expect(http.request_count(zone.jwks_url)).to eq(1)
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
