# frozen_string_literal: true

# Shared conformance examples for the token-endpoint discovery cache rows of
# keycard-sdk-spec specs/oauth-client/token-exchange.md (rows 8-13) and
# client-credentials.md (rows 7-12): base.md "Metadata failures are not
# sticky". The including group defines `zone`, `token_payload`, `client(http,
# **options)` and `request(client)` (one token request against the client).
RSpec.shared_examples "token-endpoint discovery is not sticky" do |rows| # rubocop:disable Metrics/BlockLength
  def discovery_http(&metadata_handler)
    FakeHTTPClient.new do |url, _params|
      url == zone.metadata_url ? metadata_handler.call : json_response(token_payload)
    end
  end

  it "#{rows[0]}: a network error during discovery caches nothing; the next call discovers again and succeeds" do
    attempts = 0
    http = discovery_http do
      attempts += 1
      raise Keycardai::OAuth::NetworkError, "connection refused" if attempts == 1

      json_response(zone.metadata)
    end
    subject = client(http)

    expect { request(subject) }.to raise_error(Keycardai::OAuth::NetworkError)
    expect(request(subject).access_token).to eq(token_payload["access_token"])
    expect(http.request_count(zone.metadata_url)).to eq(2)
  end

  it "#{rows[1]}: a 404 from discovery is a typed HTTP error and the next call discovers again" do
    attempts = 0
    http = discovery_http do
      attempts += 1
      attempts == 1 ? json_response({}, status: 404) : json_response(zone.metadata)
    end
    subject = client(http)

    expect { request(subject) }.to raise_error(Keycardai::OAuth::HTTPError) { |e| expect(e.status).to eq(404) }
    expect(http.request_count(zone.token_url)).to eq(0)
    expect(request(subject).access_token).to eq(token_payload["access_token"])
    expect(http.request_count(zone.metadata_url)).to eq(2)
  end

  it "#{rows[2]}: a caller interrupted during discovery leaves nothing behind; the next call discovers again" do
    attempts = 0
    http = discovery_http do
      attempts += 1
      raise Timeout::Error, "deadline" if attempts == 1

      json_response(zone.metadata)
    end
    subject = client(http)

    expect { request(subject) }.to raise_error(Timeout::Error)
    expect(request(subject).access_token).to eq(token_payload["access_token"])
    expect(http.request_count(zone.metadata_url)).to eq(2)
  end

  it "#{rows[3]}: concurrent cold-cache calls perform a single discovery request" do
    gate = Queue.new
    http = discovery_http do
      gate.pop
      json_response(zone.metadata)
    end
    subject = client(http)

    threads = Array.new(4) { Thread.new { request(subject) } }
    Thread.pass until threads.any? { |t| t.status == "sleep" }
    gate << :go
    threads.each(&:join)

    expect(http.request_count(zone.metadata_url)).to eq(1)
    expect(http.request_count(zone.token_url)).to eq(4)
  end

  it "#{rows[4]}: a call after discovery_ttl has elapsed discovers again" do
    now = Time.at(1_700_000_000)
    http = discovery_http { json_response(zone.metadata) }
    subject = client(http, discovery_ttl: 60, clock: -> { now })

    request(subject)
    now += 60
    request(subject)
    expect(http.request_count(zone.metadata_url)).to eq(1)

    now += 1
    request(subject)
    expect(http.request_count(zone.metadata_url)).to eq(2)
  end

  it "#{rows[5]}: metadata without token_endpoint is a typed invalid_metadata error, and is not cached" do
    attempts = 0
    http = discovery_http do
      attempts += 1
      attempts == 1 ? json_response(zone.metadata.except("token_endpoint")) : json_response(zone.metadata)
    end
    subject = client(http)

    expect { request(subject) }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("invalid_metadata") }
    expect(http.request_count(zone.token_url)).to eq(0)
    expect(request(subject).access_token).to eq(token_payload["access_token"])
    expect(http.request_count(zone.metadata_url)).to eq(2)
  end

  it "never substitutes a convention-derived endpoint for a failed discovery" do
    http = discovery_http { raise Keycardai::OAuth::NetworkError, "connection refused" }
    subject = client(http)

    expect { request(subject) }.to raise_error(Keycardai::OAuth::NetworkError)
    expect(http.requests).to eq([zone.metadata_url])
  end
end # rubocop:enable Metrics/BlockLength
