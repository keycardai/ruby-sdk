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

  it "1a: an oversized 429 without Retry-After starts no retry delay" do
    oversized = -> { raise Keycardai::OAuth::ResponseBodyTooLargeError.new(status: 429) }
    client, http = subject_with(oversized)
    expect { client.request_token }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |err|
      expect(err.status).to eq(429)
    end
    expect(client.request_token.access_token).to eq("at")
    expect(http.request_count(zone.metadata_url)).to eq(2)
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

  it "2: rejects invalid Retry-After dates, including normalized calendar dates" do
    day = clock.call + 5
    [
      day.strftime("%a, %d %b %Y %H:%M GMT"),
      "#{day.httpdate} junk",
      day.strftime("%a, 32 %b %Y %T GMT")
    ].each do |header|
      client, http = subject_with(unavailable(429, header))
      expect { client.request_token }.to raise_error(Keycardai::OAuth::HTTPError)
      expect(client.request_token.access_token).to eq("at")
      expect(http.request_count(zone.metadata_url)).to eq(2)
    end
  end

  it "2: accepts space- and zero-padded asctime day numbers" do
    time = Time.utc(2024, 11, 6, 12)
    retry_state = Keycardai::OAuth.const_get(:MetadataRetry).new(-> { time })
    ["Wed Nov  6 12:00:05 2024", "Wed Nov 06 12:00:05 2024"].each_with_index do |header, issuer|
      error = Keycardai::OAuth::HTTPError.new("unavailable", status: 429, retry_after: header)
      expect { retry_state.fetch(issuer) { raise error } }.to raise_error(Keycardai::OAuth::HTTPError)
      expect { retry_state.fetch(issuer) { flunk("unexpected fetch") } }.to raise_error(Keycardai::OAuth::HTTPError)
    end
  end

  it "2: reads Retry-After defensively from unsupported or symbol-keyed headers" do
    response = Keycardai::OAuth::HTTP::Response
    expect(response.new(status: 429, headers: nil, body: "").retry_after).to be_nil
    expect(response.new(status: 429, headers: { "Retry-After": ["5"] }, body: "").retry_after).to eq("5")
  end

  it "3: uses monotonic deadlines, independent of later wall time changes" do
    ticks = 0
    retry_state = Keycardai::OAuth.const_get(:MetadataRetry).new(clock, monotonic_clock: -> { ticks })
    error = Keycardai::OAuth::HTTPError.new("unavailable", status: 503, retry_after: (clock.call + 5).httpdate)
    expect { retry_state.fetch(:issuer) { raise error } }.to raise_error(Keycardai::OAuth::HTTPError)
    clock.sleep(3600)
    expect { retry_state.fetch(:issuer) { flunk("unexpected fetch") } }.to raise_error(Keycardai::OAuth::HTTPError)
    ticks = 5
    expect(retry_state.fetch(:issuer) { ticks * 2 }).to eq(10)
  end

  it "3: the default client keeps its retry delay when wall time jumps" do
    wall = Time.utc(2025, 1, 1)
    allow(Time).to receive(:now) { wall }
    failure = unavailable(503, "60")
    http = FakeHTTPClient.new do |url|
      if url == zone.token_url
        json_response({ "access_token" => "at", "token_type" => "Bearer" })
      else
        response = failure
        failure = nil
        response ? response.call : json_response(zone.metadata)
      end
    end
    client = Keycardai::OAuth::ClientCredentialsClient.new(issuer: zone.issuer, http_client: http)
    expect { client.request_token }.to raise_error(Keycardai::OAuth::HTTPError)
    wall += 3600
    expect { client.request_token }.to raise_error(Keycardai::OAuth::HTTPError)
    expect(http.request_count(zone.metadata_url)).to eq(1)
  end

  it "3: bounds shared retry state and ignores a failure after concurrent invalidation" do
    retry_state = Keycardai::OAuth.const_get(:MetadataRetry).new(clock)
    error = Keycardai::OAuth::NetworkError.new("unavailable")
    129.times { |i| expect { retry_state.fetch(i) { raise error } }.to raise_error(Keycardai::OAuth::NetworkError) }
    expect { retry_state.fetch(128) { flunk("unexpected fetch") } }.to raise_error(Keycardai::OAuth::NetworkError)
    expect(retry_state.fetch(0) { clock.call }).to eq(clock.call)
    entered = Queue.new
    release = Queue.new
    worker = Thread.new do
      retry_state.fetch(:issuer) do
        entered << true
        release.pop
        raise error
      end
    rescue Keycardai::OAuth::NetworkError => e
      e
    end
    entered.pop
    retry_state.clear
    release << true
    expect(worker.value).to equal(error)
    expect(retry_state.fetch(:issuer) { clock.call }).to eq(clock.call)
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
