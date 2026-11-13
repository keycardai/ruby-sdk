# frozen_string_literal: true

require "tmpdir"

# Conformance suite for keycard-sdk-spec specs/oauth-client/device-authorization.md
# at spec-version 4. Each example names the row of the spec's Unit Tests table
# it covers. Ruby errors have no retryable signal (SDK-6), so the rows that
# say "retryable" check the error class, code, and HTTP status instead.
RSpec.describe Keycardai::OAuth::DeviceAuthorizationClient do
  let(:zone) { ZoneFixture.new }
  let(:now) { Time.utc(2026, 1, 1) }
  let(:token_payload) do
    { "access_token" => "at_device", "token_type" => "Bearer", "expires_in" => 3600,
      "refresh_token" => "rt_device", "id_token" => "id.token.value" }
  end
  let(:device_payload) do
    { "device_code" => "dc_123", "user_code" => "WDJB-MJHT", "verification_uri" => "https://acme.test/device",
      "verification_uri_complete" => "https://acme.test/device?user_code=WDJB-MJHT",
      "expires_in" => 600, "interval" => 5 }
  end

  def oauth_error(code, status: 400)
    json_response({ "error" => code }, status: status)
  end

  # A zone that serves metadata, one device authorization response, and the
  # given poll responses in order.
  def zone_http(polls: [], device: json_response(device_payload), metadata: zone.metadata(device: true))
    queue = polls.dup
    FakeHTTPClient.new do |url, _params|
      case url
      when zone.metadata_url then json_response(metadata)
      when zone.device_authorization_url then device
      when zone.token_url then queue.shift || raise("unexpected poll")
      end
    end
  end

  def client(http, **options)
    options = { client_id: "cid" }.merge(options)
    described_class.new(issuer: zone.issuer, http_client: http, clock: -> { now }, **options)
  end

  def parsed_metadata(document)
    Keycardai::OAuth::Discovery.parse_metadata(zone.issuer, JSON.dump(document))
  end

  def authorization(device_code: "dc_123")
    Keycardai::OAuth::DeviceAuthorization.new(
      device_code: device_code, user_code: "WDJB-MJHT", verification_uri: "https://acme.test/device",
      expires_in: 600, interval: 5, expires_at: now + 600
    )
  end

  def sole_call(http, url)
    calls = http.calls.select { |call| call.url == url }
    expect(calls.size).to eq(1)
    calls.first
  end

  # A credential that returns both a header and form fields, so a test sees
  # each one merged into the request. It records every call.
  let(:recording_credential) do
    Class.new do
      attr_reader :calls

      def initialize
        @calls = []
      end

      def client_authentication(issuer:, endpoint:)
        @calls << [issuer, endpoint]
        Keycardai::OAuth::ClientAuthentication.new(
          headers: { "X-Client-Auth" => "header-#{@calls.size}" },
          params: { "client_assertion" => "assertion-#{@calls.size}", "client_assertion_type" => "jwt-bearer" }
        )
      end
    end.new
  end

  describe "request device authorization" do
    it "1: POSTs the credential's headers and form fields, a space-joined scope, and one resource per entry" do
      http = zone_http
      client(http, client_id: nil, credential: recording_credential)
        .request_device_authorization(scopes: %w[openid profile], resources: ["https://a.acme.test", "https://b.acme.test"])

      call = sole_call(http, zone.device_authorization_url)
      expect(call.params).to eq([
                                  ["scope", "openid profile"],
                                  ["resource", "https://a.acme.test"],
                                  ["resource", "https://b.acme.test"],
                                  %w[client_assertion assertion-1],
                                  %w[client_assertion_type jwt-bearer]
                                ])
      expect(call.headers).to eq("Accept" => "application/json", "X-Client-Auth" => "header-1")
      expect(recording_credential.calls).to eq([[zone.issuer, zone.device_authorization_url]])
    end

    it "2: a public client sends client_id in the body and no Authorization header" do
      http = zone_http
      client(http).request_device_authorization

      call = sole_call(http, zone.device_authorization_url)
      expect(call.params).to eq([%w[client_id cid]])
      expect(call.headers).to eq("Accept" => "application/json")
    end

    it "5: a response without interval gets interval 5 and expires_at = clock time + expires_in" do
      http = zone_http(device: json_response(device_payload.except("interval", "verification_uri_complete")))

      result = client(http).request_device_authorization

      expect(result).to eq(Keycardai::OAuth::DeviceAuthorization.new(
                             device_code: "dc_123", user_code: "WDJB-MJHT",
                             verification_uri: "https://acme.test/device", verification_uri_complete: nil,
                             expires_in: 600, interval: 5, expires_at: Time.utc(2026, 1, 1, 0, 10, 0)
                           ))
    end

    it "parses every field of a full response" do
      http = zone_http(device: json_response(device_payload.merge("interval" => 7)))

      expect(client(http).request_device_authorization).to eq(Keycardai::OAuth::DeviceAuthorization.new(
                                                                device_code: "dc_123", user_code: "WDJB-MJHT",
                                                                verification_uri: "https://acme.test/device",
                                                                verification_uri_complete: "https://acme.test/device?user_code=WDJB-MJHT",
                                                                expires_in: 600, interval: 7,
                                                                expires_at: Time.utc(2026, 1, 1, 0, 10, 0)
                                                              ))
    end

    [
      { row: "6", name: "without device_code", payload: ->(p) { p.except("device_code") },
        message: "device authorization response lacks a valid device_code" },
      { row: "6", name: "without user_code", payload: ->(p) { p.except("user_code") },
        message: "device authorization response lacks a valid user_code" },
      { row: "6", name: "without verification_uri", payload: ->(p) { p.except("verification_uri") },
        message: "device authorization response lacks a valid verification_uri" },
      { row: "6", name: "without expires_in", payload: ->(p) { p.except("expires_in") },
        message: "device authorization response lacks a valid expires_in" },
      { row: "6", name: "with expires_in as a string", payload: ->(p) { p.merge("expires_in" => "600") },
        message: "device authorization response lacks a valid expires_in" },
      { row: "-", name: "with verification_uri_complete as a number",
        payload: ->(p) { p.merge("verification_uri_complete" => 42) },
        message: "device authorization response lacks a valid verification_uri_complete" },
      { row: "25", name: "with interval 0", payload: ->(p) { p.merge("interval" => 0) },
        message: "device authorization response has an interval that is not a positive integer: 0" },
      { row: "25", name: "with interval -1", payload: ->(p) { p.merge("interval" => -1) },
        message: "device authorization response has an interval that is not a positive integer: -1" },
      { row: "25", name: 'with interval "5"', payload: ->(p) { p.merge("interval" => "5") },
        message: 'device authorization response has an interval that is not a positive integer: "5"' }
    ].each do |example|
      it "#{example[:row]}: a response #{example[:name]} is a ProtocolError with code invalid_response" do
        http = zone_http(device: json_response(example[:payload].call(device_payload)))

        expect { client(http).request_device_authorization }
          .to raise_error(Keycardai::OAuth::ProtocolError, example[:message]) { |e|
            expect(e.code).to eq("invalid_response")
          }
      end
    end

    it "raises the zone's OAuth error, such as invalid_target" do
      http = zone_http(device: oauth_error("invalid_target"))

      expect { client(http).request_device_authorization(resources: ["https://unknown.acme.test"]) }
        .to raise_error(Keycardai::OAuth::OAuthError, "device authorization endpoint returned invalid_target") { |e|
          expect([e.error, e.status]).to eq(["invalid_target", 400])
        }
    end
  end

  describe "client configuration" do
    [
      { row: "3", name: "both credential and client_id", options: ->(cred) { { credential: cred, client_id: "cid" } },
        message: "pass a credential or client_id, not both" },
      { row: "3", name: "neither credential nor client_id", options: ->(_cred) { { client_id: nil } },
        message: "pass a credential or a client_id" },
      { row: "3", name: "an empty client_id", options: ->(_cred) { { client_id: "" } },
        message: "pass a credential or a client_id" },
      { row: "23", name: "a credential without client_authentication",
        options: ->(_cred) { { client_id: nil, credential: Object.new } },
        message: "Object does not provide client authentication" },
      { row: "-", name: "a clock that does not respond to call", options: ->(_cred) { { clock: nil } },
        message: "clock must respond to call" },
      { row: "-", name: "a timeout of 0", options: ->(_cred) { { timeout: 0 } },
        message: "timeout 0 is not a positive number of seconds" },
      { row: "-", name: "a nil discovery_ttl", options: ->(_cred) { { discovery_ttl: nil } },
        message: "discovery_ttl nil is not 0 or more seconds" },
      { row: "-", name: "metadata without an issuer",
        options: lambda { |_cred|
          { issuer: nil, metadata: Keycardai::OAuth::AuthorizationServerMetadata.new(issuer: nil) }
        },
        message: "the metadata has no issuer" }
    ].each do |example|
      it "#{example[:row]}: #{example[:name]} is a configuration error before any request" do
        http = zone_http

        expect { client(http, **example[:options].call(recording_credential)) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, example[:message])
        expect(http.calls).to be_empty
      end
    end

    it "accepts an issuer that differs from the metadata's issuer only by a trailing slash" do
      http = zone_http
      described_class.new(issuer: "https://acme.test/", metadata: parsed_metadata(zone.metadata(device: true)),
                          client_id: "cid", http_client: http).request_device_authorization

      expect(http.requests).to eq([zone.device_authorization_url])
    end

    it "rejects an issuer that differs from the metadata's issuer" do
      expect do
        described_class.new(issuer: "https://other.test", metadata: parsed_metadata(zone.metadata(device: true)),
                            client_id: "cid")
      end.to raise_error(Keycardai::OAuth::ConfigurationError,
                         "issuer https://other.test does not match the metadata issuer https://acme.test")
    end
  end

  describe "endpoints" do
    device_url = "https://acme.test/oauth/device_authorization"

    # Each case names the metadata change and the operation that fails. The
    # operation raises ConfigurationError and does not send a request to the
    # endpoint, with the metadata pre-discovered or discovered.
    [
      { row: "4", name: "no device_authorization_endpoint", change: ->(m) { m.except("device_authorization_endpoint") },
        operation: :request, message: "metadata for https://acme.test has no device_authorization_endpoint" },
      { row: "30", name: "no token_endpoint", change: ->(m) { m.except("token_endpoint") },
        operation: :poll, message: "metadata for https://acme.test has no token_endpoint" },
      { row: "30", name: "an ftp device_authorization_endpoint",
        change: ->(m) { m.merge("device_authorization_endpoint" => "ftp://acme.test/device") },
        operation: :request,
        message: 'device_authorization_endpoint "ftp://acme.test/device" is not an http or https URL' },
      { row: "30", name: "a token_endpoint that is not a URL",
        change: ->(m) { m.merge("token_endpoint" => "not a url") },
        operation: :poll, message: 'token_endpoint "not a url" is not an http or https URL' },
      { row: "30", name: "a relative token_endpoint",
        change: ->(m) { m.merge("token_endpoint" => "/oauth/token") },
        operation: :poll, message: 'token_endpoint "/oauth/token" is not an http or https URL' },
      { row: "30", name: "a token_endpoint that is not a string",
        change: ->(m) { m.merge("token_endpoint" => 42) },
        operation: :poll, message: "token_endpoint 42 is not an http or https URL" }
    ].each do |example|
      [
        { source: "pre-discovered", requests: [],
          build: ->(http, metadata) { client(http, issuer: nil, metadata: parsed_metadata(metadata)) } },
        { source: "discovered", requests: ["https://acme.test/.well-known/oauth-authorization-server"],
          build: ->(http, _metadata) { client(http) } }
      ].each do |source|
        it "#{example[:row]}: #{source[:source]} metadata with #{example[:name]} fails before a request" do
          metadata = example[:change].call(zone.metadata(device: true))
          http = zone_http(metadata: metadata)
          device = instance_exec(http, metadata, &source[:build])
          run = lambda do
            example[:operation] == :request ? device.request_device_authorization : device.poll_token(authorization)
          end

          expect(&run).to raise_error(Keycardai::OAuth::ConfigurationError, example[:message])
          expect(http.requests).to eq(source[:requests])
        end
      end
    end

    it "30: discovered metadata the grant cannot use is fetched again on the next call" do
      http = zone_http(metadata: zone.metadata)
      device = client(http)

      2.times do
        expect { device.request_device_authorization }.to raise_error(Keycardai::OAuth::ConfigurationError)
      end
      expect(http.requests).to eq([zone.metadata_url, zone.metadata_url])
    end

    it "discovers once and reuses the metadata within discovery_ttl, then discovers again" do
      clock_time = now
      http = zone_http(polls: [json_response(token_payload), json_response(token_payload)])
      device = described_class.new(issuer: zone.issuer, client_id: "cid", http_client: http, clock: -> { clock_time },
                                   discovery_ttl: 60)

      device.request_device_authorization
      device.poll_token(authorization)
      clock_time += 61
      device.poll_token(authorization)

      expect(http.requests).to eq([zone.metadata_url, device_url, zone.token_url, zone.metadata_url, zone.token_url])
    end

    it "30: discovered metadata with a bad token_endpoint is fetched again after a device authorization request" do
      http = zone_http(metadata: zone.metadata(device: true).merge("token_endpoint" => "ftp://acme.test/token"))
      device = client(http)

      2.times { device.request_device_authorization }

      expect(http.requests).to eq([zone.metadata_url, device_url, zone.metadata_url, device_url])
    end

    [
      { name: "a 503", response: -> { json_response({}, status: 503) },
        error: Keycardai::OAuth::HTTPError, message: "discovery for https://acme.test returned HTTP 503" },
      { name: "a network error",
        response: -> { raise Keycardai::OAuth::NetworkError, "request to acme.test failed: Errno::ECONNREFUSED" },
        error: Keycardai::OAuth::NetworkError, message: "request to acme.test failed: Errno::ECONNREFUSED" }
    ].each do |example|
      it "raises a discovery failure from #{example[:name]} as is, and the next call fetches again" do
        responses = [example[:response], -> { json_response(zone.metadata(device: true)) }]
        http = FakeHTTPClient.new do |url, _params|
          url == zone.metadata_url ? instance_exec(&responses.shift) : json_response(device_payload)
        end
        device = client(http)

        expect { device.request_device_authorization }.to raise_error(example[:error], example[:message])
        device.request_device_authorization

        expect(http.requests).to eq([zone.metadata_url, zone.metadata_url, device_url])
      end
    end

    it "uses pre-discovered metadata without a discovery request" do
      http = zone_http

      described_class.new(metadata: parsed_metadata(zone.metadata(device: true)), client_id: "cid", http_client: http)
                     .request_device_authorization

      expect(http.requests).to eq([device_url])
    end

    it "uses metadata built by hand from its endpoints" do
      http = zone_http(polls: [json_response(token_payload)])
      metadata = Keycardai::OAuth::AuthorizationServerMetadata.new(
        issuer: zone.issuer, token_endpoint: zone.token_url, device_authorization_endpoint: device_url
      )
      device = described_class.new(metadata: metadata, client_id: "cid", http_client: http)

      device.poll_token(device.request_device_authorization)

      expect(http.requests).to eq([device_url, zone.token_url])
    end

    it "sends the timeout on discovery, the device authorization request, and the poll" do
      http = zone_http(polls: [json_response(token_payload)])
      device = client(http, timeout: 3)

      device.poll_token(device.request_device_authorization)

      expect(http.calls.map { |call| [call.url, call.timeout] })
        .to eq([[zone.metadata_url, 3], [device_url, 3], [zone.token_url, 3]])
    end
  end

  describe "poll once" do
    it "7: POSTs the device_code grant with the same client authentication and no resource or scope" do
      http = zone_http(polls: [json_response(token_payload)])
      device = client(http, client_id: nil, credential: recording_credential)

      device.request_device_authorization(scopes: ["openid"], resources: ["https://a.acme.test"])
      token = device.poll_token(authorization)

      call = sole_call(http, zone.token_url)
      expect(call.params).to eq([
                                  ["grant_type", "urn:ietf:params:oauth:grant-type:device_code"],
                                  %w[device_code dc_123],
                                  %w[client_assertion assertion-2],
                                  %w[client_assertion_type jwt-bearer]
                                ])
      expect(call.headers).to eq("Accept" => "application/json", "X-Client-Auth" => "header-2")
      expect(recording_credential.calls).to eq([[zone.issuer, zone.device_authorization_url],
                                                [zone.issuer, zone.token_url]])
      expect(token).to have_attributes(access_token: "at_device", refresh_token: "rt_device",
                                       id_token: "id.token.value")
    end

    it "7: a public client polls with client_id in the body" do
      http = zone_http(polls: [json_response(token_payload)])
      client(http).poll_token(authorization)

      expect(sole_call(http, zone.token_url).params)
        .to eq([["grant_type", "urn:ietf:params:oauth:grant-type:device_code"], %w[device_code dc_123],
                %w[client_id cid]])
    end

    [
      { name: "authorization_pending", response: -> { oauth_error("authorization_pending") }, status: 400 },
      { name: "slow_down", response: -> { oauth_error("slow_down") }, status: 400 },
      { name: "access_denied", response: -> { oauth_error("access_denied") }, status: 400 },
      # Row 29: the 503 status, not the code, is what makes this one
      # retryable. Ruby has no retryable signal, so the status is the check.
      { name: "access_denied on a 503 (29)", response: -> { oauth_error("access_denied", status: 503) }, status: 503 }
    ].each do |example|
      it "raises #{example[:name]} as an OAuthError with its code and status" do
        http = zone_http(polls: [instance_exec(&example[:response])])
        code = example[:name].split.first

        expect { client(http).poll_token(authorization) }
          .to raise_error(Keycardai::OAuth::OAuthError, "token endpoint returned #{code}") { |e|
            expect([e.error, e.status]).to eq([code, example[:status]])
          }
      end
    end

    [
      { name: "an empty device_code", authorization: -> { authorization(device_code: "") } },
      { name: "a device_code that is not a string", authorization: -> { authorization(device_code: 42) } },
      { name: "nil in place of a DeviceAuthorization", authorization: -> {} }
    ].each do |example|
      it "#{example[:name]} is a configuration error; no request is sent" do
        http = zone_http

        expect { client(http).poll_token(instance_exec(&example[:authorization])) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, "the device authorization has no device_code")
        expect(http.calls).to be_empty
      end
    end
  end

  # Rows 31 and 32 through the real NetHTTPClient, which decompresses gzip
  # while it reads the body.
  describe "a body that does not decompress" do
    after { @server&.close }

    def served_client(device:, token:)
      @server = RawHTTPServer.new do |_method, path|
        { "/oauth/device_authorization" => device, "/oauth/token" => token }.fetch(path)
      end
      metadata = parsed_metadata(
        zone.metadata.merge("device_authorization_endpoint" => @server.url("/oauth/device_authorization"),
                            "token_endpoint" => @server.url("/oauth/token"))
      )
      described_class.new(metadata: metadata, client_id: "cid", clock: -> { now })
    end

    it "31: poll once with a 200 is a ProtocolError invalid_response" do
      device = served_client(device: nil, token: RawHTTPServer.corrupt_gzip(200))

      expect { device.poll_token(authorization) }
        .to raise_error(Keycardai::OAuth::ProtocolError,
                        "token response body does not decompress: Zlib::DataError") { |e|
          expect(e.code).to eq("invalid_response")
          expect(e.cause).to be_an_instance_of(Zlib::DataError)
        }
    end

    it "31: the device authorization request with a 200 is a ProtocolError invalid_response" do
      device = served_client(device: RawHTTPServer.corrupt_gzip(200), token: nil)

      expect { device.request_device_authorization }
        .to raise_error(Keycardai::OAuth::ProtocolError,
                        "device authorization response body does not decompress: Zlib::DataError") { |e|
          expect(e.code).to eq("invalid_response")
          expect(e.cause).to be_an_instance_of(Zlib::DataError)
        }
    end

    [
      { name: "poll once", device: nil, token: 503, run: ->(device) { device.poll_token(authorization) },
        message: "token endpoint returned HTTP 503" },
      { name: "the device authorization request", device: 503, token: nil,
        run: lambda(&:request_device_authorization), message: "device authorization endpoint returned HTTP 503" }
    ].each do |example|
      it "32: #{example[:name]} with a 503 is an HTTPError with that status, not an OAuthError" do
        device = served_client(device: example[:device] && RawHTTPServer.corrupt_gzip(example[:device]),
                               token: example[:token] && RawHTTPServer.corrupt_gzip(example[:token]))

        expect { instance_exec(device, &example[:run]) }
          .to raise_error(Keycardai::OAuth::HTTPError, example[:message]) { |e|
            expect(e).to be_an_instance_of(Keycardai::OAuth::HTTPError)
            expect(e.status).to eq(503)
          }
      end
    end
  end

  it "22: a WebIdentity flow signs a new assertion per request with aud set to that request's endpoint" do
    Dir.mktmpdir do |dir|
      credential = Keycardai::OAuth::WebIdentity.new(client_id: "cid", key_id: "device-key", storage_dir: dir)
      http = zone_http(polls: [oauth_error("authorization_pending"), json_response(token_payload)])
      device = client(http, client_id: nil, credential: credential)

      flow = device.request_device_authorization
      expect { device.poll_token(flow) }.to raise_error(Keycardai::OAuth::OAuthError)
      device.poll_token(flow)

      claims = http.calls.select { |call| call.verb == :post }.map do |call|
        decode_jwt_part(call.params.to_h.fetch("client_assertion").split(".")[1])
      end
      expect(claims.map { |claim| claim["aud"] })
        .to eq([zone.device_authorization_url, zone.token_url, zone.token_url])
      expect(claims.map { |claim| claim["jti"] }.uniq.size).to eq(3)
    end
  end

  it "24: a token for two resources has no resource association, even when the response names one" do
    http = zone_http(polls: [json_response(token_payload.merge("resource" => "https://a.acme.test"))])
    device = client(http)

    device.request_device_authorization(resources: ["https://a.acme.test", "https://b.acme.test"])
    token = device.poll_token(authorization)

    expect(token.access_token).to eq("at_device")
    expect(Keycardai::OAuth::TokenResponse.members).not_to include(:resource)
    expect(token.raw["resource"]).to eq("https://a.acme.test")
  end
end
