# frozen_string_literal: true

RSpec.describe "Base metadata caching" do
  let(:zone) { ZoneFixture.new }
  let(:clock) { FakeClock.new }

  def subject_with(*failures)
    http = FakeHTTPClient.new do |url|
      next json_response({ "access_token" => "at", "token_type" => "Bearer" }) if url == zone.token_url

      failure = failures.shift
      failure ? failure.call : json_response(zone.metadata)
    end
    client = Keycardai::OAuth::ClientCredentialsClient.new(
      issuer: zone.issuer, http_client: http, clock: clock, discovery_ttl: 60
    )
    [client, http]
  end

  def unavailable(status, header)
    -> { Keycardai::OAuth::HTTP::Response.new(status: status, headers: { "retry-after" => [header] }, body: "{}") }
  end

  def network_error
    -> { raise Keycardai::OAuth::NetworkError, "connection refused" }
  end

  [429, 503].product([5, 120], %i[seconds date]).each do |status, seconds, format|
    it "2: honors HTTP #{status} Retry-After of #{seconds} seconds as #{format}, capped at 60 seconds" do
      header = format == :date ? (clock.call + seconds).httpdate : seconds.to_s
      client, http = subject_with(unavailable(status, header))
      expect { client.request_token }.to raise_error(Keycardai::OAuth::HTTPError)
      clock.sleep([60, seconds].min - 0.5)
      expect { client.request_token }.to raise_error(Keycardai::OAuth::HTTPError)
      expect(http.request_count(zone.metadata_url)).to eq(1)
      clock.sleep(0.5)
      expect(client.request_token.access_token).to eq("at")
    end
  end

  it "3: exponentially backs off repeated failures, capping jittered delays at 30 seconds" do
    client, http = subject_with(*Array.new(7, network_error))
    [1, 2, 4, 8, 16, 32, 64].each_with_index do |step, i|
      expect { client.request_token }.to raise_error(Keycardai::OAuth::NetworkError)
      lower = [30, step * 0.8].min - 0.01
      clock.sleep(lower)
      expect { client.request_token }.to raise_error(Keycardai::OAuth::NetworkError)
      expect(http.request_count(zone.metadata_url)).to eq(i + 1)
      clock.sleep([30, step * 1.2].min - lower + 0.01)
    end
    expect(client.request_token.access_token).to eq("at")
  end

  it "4: a successful fetch resets the backoff for the next refresh" do
    client, = subject_with(network_error, network_error, nil, network_error)
    [1.2, 2.4].each do |delay|
      expect { client.request_token }.to raise_error(Keycardai::OAuth::NetworkError)
      clock.sleep(delay)
    end
    expect(client.request_token.access_token).to eq("at")
    clock.sleep(61)
    expect { client.request_token }.to raise_error(Keycardai::OAuth::NetworkError)
    clock.sleep(1.2)
    expect(client.request_token.access_token).to eq("at")
  end

  it "5: a deterministic failure does not start transient backoff" do
    client, = subject_with(-> { json_response(zone.metadata.except("token_endpoint")) })
    expect { client.request_token }.to raise_error(Keycardai::OAuth::ProtocolError)
    expect(client.request_token.access_token).to eq("at")
  end

  it "6: a caller's deadline does not start backoff" do
    client, = subject_with(-> { raise Timeout::Error, "caller deadline" })
    expect { client.request_token }.to raise_error(Timeout::Error, "caller deadline")
    expect(client.request_token.access_token).to eq("at")
  end
end
