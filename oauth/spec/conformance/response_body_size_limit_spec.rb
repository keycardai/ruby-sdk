# frozen_string_literal: true

require "json"
require "socket"
require "stringio"
require "zlib"

RSpec.describe "Response body size limit (base.md & device-authorization.md)" do
  let(:limit) { Keycardai::OAuth::MAX_RESPONSE_BODY_BYTES }

  def gzip(data)
    io = StringIO.new
    gz = Zlib::GzipWriter.new(io)
    gz.write(data)
    gz.close
    io.string
  end

  def make_token_json(extra_bytes)
    prefix = '{"access_token":"tok","token_type":"Bearer","pad":"'
    suffix = '"}'
    pad = "a" * (limit - prefix.bytesize - suffix.bytesize + extra_bytes)
    "#{prefix}#{pad}#{suffix}"
  end

  def json_response(status, payload)
    [status, { "Content-Type" => "application/json" }, JSON.dump(payload)]
  end

  def read_request_path(sock)
    request_line = sock.gets
    return nil unless request_line

    content_length = 0
    while (line = sock.gets) && line != "\r\n"
      content_length = Regexp.last_match(1).to_i if line =~ /\AContent-Length:\s*(\d+)/i
    end
    sock.read(content_length) if content_length.positive?
    request_line.split[1]
  end

  def serve_client(sock, handler)
    path = read_request_path(sock)
    return unless path

    status, headers, body = handler.call(path)
    header_lines = headers.map { |k, v| "#{k}: #{v}" }.join("\r\n")
    head = "HTTP/1.1 #{status} OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n#{header_lines}\r\n\r\n"
    sock.write("#{head}#{body}")
  rescue IOError, Errno::EPIPE, Errno::ECONNRESET
    nil
  ensure
    sock&.close
  end

  def with_http_server(handler)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop { Thread.new(server.accept) { |sock| serve_client(sock, handler) } }
    rescue IOError
      nil
    end
    yield "http://127.0.0.1:#{server.addr[1]}"
  ensure
    server&.close
    thread&.kill
  end

  it "1: rejects a gzip token response that inflates above 1 MiB with invalid_response" do
    compressed = gzip(make_token_json(1024))
    expect(compressed.bytesize).to be < limit
    issuer_ref = nil

    handler = lambda do |path|
      if path == "/.well-known/oauth-authorization-server"
        json_response(200, { issuer: issuer_ref, token_endpoint: "#{issuer_ref}/token" })
      else
        [200, { "Content-Type" => "application/json", "Content-Encoding" => "gzip" }, compressed]
      end
    end

    with_http_server(handler) do |url|
      issuer_ref = url
      client = Keycardai::OAuth::ClientCredentialsClient.new(issuer: url, client_id: "cid", client_secret: "csec")
      expect { client.request_token }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |err|
        expect(err).to be_a(Keycardai::OAuth::ProtocolError)
        expect(err.code).to eq("invalid_response")
        expect(err.status).to eq(200)
        expect(err.retryable?).to be(true)
      end
    end
  end

  it "1: accepts an exact 1 MiB decoded response and rejects 1 MiB + 1 byte" do
    exact = make_token_json(0)
    over = make_token_json(1)
    send_over = false
    issuer_ref = nil

    handler = lambda do |path|
      if path == "/.well-known/oauth-authorization-server"
        json_response(200, { issuer: issuer_ref, token_endpoint: "#{issuer_ref}/token" })
      else
        [200, { "Content-Type" => "application/json" }, send_over ? over : exact]
      end
    end

    with_http_server(handler) do |url|
      issuer_ref = url
      client = Keycardai::OAuth::ClientCredentialsClient.new(issuer: url, client_id: "cid", client_secret: "csec")
      expect(client.request_token.access_token).to eq("tok")

      send_over = true
      expect { client.request_token }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError)
    end
  end

  it "1a: does not negatively cache oversized discovery responses on 200, 429, or 503 and maps JWKS overflows" do
    [200, 429, 503].each do |status|
      calls = 0
      fail_first = true
      issuer_ref = nil

      handler = lambda do |path|
        calls += 1
        if fail_first
          [status, { "Content-Type" => "application/json" }, make_token_json(512)]
        elsif path == "/.well-known/oauth-authorization-server"
          json_response(200, { issuer: issuer_ref, jwks_uri: "#{issuer_ref}/jwks" })
        else
          [200, { "Content-Type" => "application/json" }, '{"keys":[]}']
        end
      end

      with_http_server(handler) do |url|
        issuer_ref = url
        clock = FakeClock.new
        keyring = Keycardai::OAuth::JWKSKeyring.new(clock: clock)
        expect { keyring.key(url, "k1") }.to raise_error(Keycardai::OAuth::JWKSDiscoveryError)
        expect(calls).to eq(1)

        fail_first = false
        clock.sleep(1.2) if status == 503
        expect { keyring.key(url, "k1") }.to raise_error(Keycardai::OAuth::JWKSKeyNotFoundError)
        expect(calls).to be >= 2
      end
    end

    issuer_ref = nil
    jwks_handler = lambda do |path|
      if path == "/.well-known/oauth-authorization-server"
        json_response(200, { issuer: issuer_ref, jwks_uri: "#{issuer_ref}/jwks" })
      else
        [200, { "Content-Type" => "application/json" }, make_token_json(512)]
      end
    end

    with_http_server(jwks_handler) do |url|
      issuer_ref = url
      keyring = Keycardai::OAuth::JWKSKeyring.new
      expect { keyring.key(url, "k1") }.to raise_error(Keycardai::OAuth::JWKSFetchError)
    end
  end

  [429, 503].product([5, 120]).each do |status, seconds|
    it "1a: honors Retry-After of #{seconds} seconds on oversized HTTP #{status}, capped at 60 seconds" do
      clock = FakeClock.new
      header = seconds == 5 ? (clock.call + seconds).httpdate : seconds.to_s
      calls = 0
      issuer = nil
      handler = lambda do |path|
        if path == "/.well-known/oauth-authorization-server"
          calls += 1
          if calls == 1
            [status, { "Retry-After" => header }, make_token_json(512)]
          else
            json_response(200, { issuer: issuer, token_endpoint: "#{issuer}/token" })
          end
        else
          json_response(200, { access_token: "tok", token_type: "Bearer" })
        end
      end

      with_http_server(handler) do |url|
        issuer = url
        client = Keycardai::OAuth::ClientCredentialsClient.new(issuer: url, clock: clock)
        expect { client.request_token }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError)
        clock.sleep([60, seconds].min - 0.5)
        expect { client.request_token }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |err|
          expect(err.status).to eq(status)
          expect(err.retry_after).to eq(header)
          expect(err.retryable?).to be(true)
        end
        expect(calls).to eq(1)
        clock.sleep(0.5)
        expect(client.request_token.access_token).to eq("tok")
        expect(calls).to eq(2)
      end
    end
  end

  it "1c: rejects a 400 token response with an oversized body as non-retryable invalid_response" do
    prefix = '{"error":"invalid_grant","error_description":"'
    suffix = '"}'
    oversized_err = "#{prefix}#{"x" * (limit - prefix.bytesize - suffix.bytesize + 256)}#{suffix}"
    issuer_ref = nil

    handler = lambda do |path|
      if path == "/.well-known/oauth-authorization-server"
        json_response(200, { issuer: issuer_ref, token_endpoint: "#{issuer_ref}/token" })
      else
        [400, { "Content-Type" => "application/json" }, oversized_err]
      end
    end

    with_http_server(handler) do |url|
      issuer_ref = url
      client = Keycardai::OAuth::ClientCredentialsClient.new(issuer: url, client_id: "cid", client_secret: "csec")
      expect { client.request_token }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |err|
        expect(err.code).to eq("invalid_response")
        expect(err.status).to eq(400)
        expect(err.retryable?).to be(false)
      end
    end
  end

  it "1b: wraps oversized 429 and 503 device poll responses in DevicePollError without doubling the interval" do
    [429, 503].each do |status|
      poll_num = 0
      handler = lambda do |_path|
        poll_num += 1
        if poll_num == 1
          [400, { "Content-Type" => "application/json" }, '{"error":"slow_down"}']
        else
          [status, { "Content-Type" => "application/json" }, make_token_json(512)]
        end
      end

      with_http_server(handler) do |url|
        now = Time.at(1_000_000)
        metadata = Keycardai::OAuth::AuthorizationServerMetadata.new(
          issuer: url,
          device_authorization_endpoint: "#{url}/device",
          token_endpoint: "#{url}/token"
        )
        client = Keycardai::OAuth::DeviceAuthorizationClient.new(
          issuer: url,
          metadata: metadata,
          client_id: "cid",
          clock: -> { now },
          sleep: ->(s) { now += s }
        )
        auth = Keycardai::OAuth::DeviceAuthorization.new(
          device_code: "dev-1",
          user_code: "ABCD-1234",
          verification_uri: "#{url}/verify",
          verification_uri_complete: nil,
          expires_in: 600,
          interval: 5,
          expires_at: now + 600
        )
        expect { client.wait_for_token(auth) }.to raise_error(Keycardai::OAuth::DevicePollError) do |err|
          expect(err.interval).to eq(10)
          expect(err.cause).to be_a(Keycardai::OAuth::ResponseBodyTooLargeError)
          expect(err.cause.status).to eq(status)
        end
      end
    end
  end

  it "36: rejects oversized device poll responses on 200, 400, 429, and 503" do
    [200, 400, 429, 503].each do |status|
      handler = ->(_path) { [status, { "Content-Type" => "application/json" }, make_token_json(512)] }
      with_http_server(handler) do |url|
        metadata = Keycardai::OAuth::AuthorizationServerMetadata.new(
          issuer: url,
          device_authorization_endpoint: "#{url}/device",
          token_endpoint: "#{url}/token"
        )
        client = Keycardai::OAuth::DeviceAuthorizationClient.new(issuer: url, metadata: metadata, client_id: "cid")
        auth = Keycardai::OAuth::DeviceAuthorization.new(
          device_code: "dev-1",
          user_code: "ABCD-1234",
          verification_uri: "#{url}/verify",
          verification_uri_complete: nil,
          expires_in: 600,
          interval: 5,
          expires_at: Time.now + 600
        )
        expect { client.poll_token(auth) }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |err|
          expect(err.code).to eq("invalid_response")
          expect(err.status).to eq(status)
        end
      end
    end
  end

  it "36: wait_for_token raises invalid_response for an oversized 200 or 400 without polling again" do
    [200, 400].each do |status|
      polls = 0
      handler = lambda do |_path|
        polls += 1
        [status, { "Content-Type" => "application/json" }, make_token_json(512)]
      end

      with_http_server(handler) do |url|
        now = Time.at(1_000_000)
        metadata = Keycardai::OAuth::AuthorizationServerMetadata.new(
          issuer: url,
          device_authorization_endpoint: "#{url}/device",
          token_endpoint: "#{url}/token"
        )
        client = Keycardai::OAuth::DeviceAuthorizationClient.new(
          issuer: url,
          metadata: metadata,
          client_id: "cid",
          clock: -> { now },
          sleep: ->(s) { now += s }
        )
        auth = Keycardai::OAuth::DeviceAuthorization.new(
          device_code: "dev-1",
          user_code: "ABCD-1234",
          verification_uri: "#{url}/verify",
          verification_uri_complete: nil,
          expires_in: 600,
          interval: 5,
          expires_at: now + 600
        )
        expect { client.wait_for_token(auth) }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |err|
          expect(err.code).to eq("invalid_response")
          expect(err.status).to eq(status)
        end
        expect(polls).to eq(1)
      end
    end
  end
end
