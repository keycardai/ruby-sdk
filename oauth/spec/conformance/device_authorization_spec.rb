# frozen_string_literal: true

require "time"
require "tmpdir"

# Conformance suite for keycard-sdk-spec specs/oauth-client/device-authorization.md.
# Each example maps to a row of the spec's Unit Tests table. Row 20 does not
# apply to Ruby: the spec's Ruby cancellation row says an in-flight request is
# not interrupted. The example labelled "20 (Ruby)" checks that behavior.
# Ruby errors have no retryable signal (SDK-6), so the rows that say
# "retryable" or "not retryable" check the error type and code instead.
RSpec.describe Keycardai::OAuth::DeviceAuthorizationClient do
  let(:zone) { ZoneFixture.new }
  let(:events) { [] }
  let(:clock) { FakeClock.new(events: events) }
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

  def network_error
    Keycardai::OAuth::NetworkError.new("request to acme.test failed: Errno::ECONNREFUSED")
  end

  # A zone that serves metadata, one device authorization response, and the
  # given poll results in order. A poll result that is an exception is
  # raised, as the transport raises NetworkError. A callable is called and
  # its result returned. Each poll appends :poll to events, which the clock
  # shares.
  def zone_http(polls: [], device: json_response(device_payload), metadata: zone.metadata(device: true))
    queue = polls.dup
    FakeHTTPClient.new do |url, _params|
      case url
      when zone.metadata_url then json_response(metadata)
      when zone.device_authorization_url then device
      when zone.token_url
        events << :poll
        result = queue.shift || raise("unexpected poll")
        result = result.call if result.respond_to?(:call)
        result.is_a?(Exception) ? raise(result) : result
      end
    end
  end

  def client(http, **options)
    options = { client_id: "cid" }.merge(options)
    described_class.new(issuer: zone.issuer, http_client: http, clock: clock, sleep: clock.method(:sleep), **options)
  end

  def authorization(expires_in: 600, interval: 5)
    Keycardai::OAuth::DeviceAuthorization.new(
      device_code: "dc_123", user_code: "WDJB-MJHT", verification_uri: "https://acme.test/device",
      expires_in: expires_in, interval: interval, expires_at: clock.now + expires_in
    )
  end

  def calls_to(http, url)
    http.calls.select { |call| call.url == url }
  end

  def sole_call(http, url)
    calls = calls_to(http, url)
    expect(calls.size).to eq(1)
    calls.first
  end

  # A credential that returns both a header and form fields, so a test can
  # see each merged into the request. It records every endpoint it signs for.
  let(:recording_credential) do
    Class.new do
      attr_reader :endpoints

      def initialize
        @endpoints = []
      end

      def client_authentication(issuer:, endpoint:)
        @endpoints << [issuer, endpoint]
        Keycardai::OAuth::ClientAuthentication.new(
          headers: { "X-Client-Auth" => "header-#{@endpoints.size}" },
          params: { "client_assertion" => "assertion-#{@endpoints.size}", "client_assertion_type" => "jwt-bearer" }
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
      expect(recording_credential.endpoints).to eq([[zone.issuer, zone.device_authorization_url]])
    end

    it "2: a public client sends client_id in the body and no Authorization header" do
      http = zone_http
      client(http).request_device_authorization

      call = sole_call(http, zone.device_authorization_url)
      expect(call.params).to eq([%w[client_id cid]])
      expect(call.headers).to eq("Accept" => "application/json")
    end

    [
      { name: "both credential and client_id", options: ->(cred) { { credential: cred, client_id: "cid" } } },
      { name: "neither credential nor client_id", options: ->(_cred) { { client_id: nil } } },
      { name: "an empty client_id", options: ->(_cred) { { client_id: "" } } }
    ].each do |example|
      it "3: #{example[:name]} is a configuration error before any request" do
        http = zone_http
        expect { client(http, **example[:options].call(recording_credential)) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /credential or a client_id/)
        expect(http.calls).to be_empty
      end
    end

    it "23: a credential without client_authentication is a configuration error before any request" do
      http = zone_http
      legacy = Object.new.tap { |credential| credential.define_singleton_method(:authorization_header) { |**| nil } }

      expect { client(http, client_id: nil, credential: legacy) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /does not provide client authentication/)
      expect(http.calls).to be_empty
    end

    it "4: metadata without device_authorization_endpoint is a configuration error; no request is sent" do
      metadata = Keycardai::OAuth::Discovery.parse_metadata(zone.issuer, JSON.dump(zone.metadata))
      http = zone_http

      expect { client(http, metadata: metadata).request_device_authorization }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /device_authorization_endpoint/)
      expect(http.calls).to be_empty
    end

    it "4: discovered metadata without device_authorization_endpoint sends only the discovery request" do
      http = zone_http(metadata: zone.metadata)

      expect { client(http).request_device_authorization }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /device_authorization_endpoint/)
      expect(http.requests).to eq([zone.metadata_url])
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

    %w[device_code user_code verification_uri expires_in].each do |field|
      it "6: a response missing #{field} is a ProtocolError with code invalid_response" do
        http = zone_http(device: json_response(device_payload.except(field)))

        expect { client(http).request_device_authorization }
          .to raise_error(Keycardai::OAuth::ProtocolError, /missing #{field}/) { |e|
            expect(e.code).to eq("invalid_response")
          }
      end
    end

    it "raises the zone's OAuth error, such as invalid_target" do
      http = zone_http(device: oauth_error("invalid_target"))

      expect { client(http).request_device_authorization(resources: ["https://unknown.acme.test"]) }
        .to raise_error(Keycardai::OAuth::OAuthError, "device authorization endpoint returned invalid_target")
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
      expect(recording_credential.endpoints).to eq([[zone.issuer, zone.device_authorization_url],
                                                    [zone.issuer, zone.token_url]])
      expect(token.access_token).to eq("at_device")
    end

    it "7: a public client polls with client_id in the body" do
      http = zone_http(polls: [json_response(token_payload)])
      client(http).poll_token(authorization)

      expect(sole_call(http, zone.token_url).params)
        .to eq([["grant_type", "urn:ietf:params:oauth:grant-type:device_code"], %w[device_code dc_123],
                %w[client_id cid]])
    end

    it "raises authorization_pending as an OAuthError" do
      http = zone_http(polls: [oauth_error("authorization_pending")])

      expect { client(http).poll_token(authorization) }
        .to raise_error(Keycardai::OAuth::OAuthError) { |e| expect(e.error).to eq("authorization_pending") }
    end
  end

  describe "poll until done" do
    poll_error = Keycardai::OAuth::DevicePollError

    # Each case scripts the poll results and states the exact sequence of
    # waits and polls, and the outcome: a token, or an error with its code,
    # its next_interval, and its cause. interval is the wait_for_token input.
    [
      { row: "8", name: "authorization_pending twice, then a token",
        polls: lambda {
          [oauth_error("authorization_pending"), oauth_error("authorization_pending"), json_response(token_payload)]
        },
        events: [[:wait, 5], :poll, [:wait, 5], :poll, [:wait, 5], :poll],
        token: true },
      { row: "9", name: "slow_down, then authorization_pending, then a token",
        polls: -> { [oauth_error("slow_down"), oauth_error("authorization_pending"), json_response(token_payload)] },
        events: [[:wait, 5], :poll, [:wait, 10], :poll, [:wait, 10], :poll],
        token: true },
      { row: "10", name: "access_denied",
        polls: -> { [oauth_error("access_denied")] },
        events: [[:wait, 5], :poll],
        error: Keycardai::OAuth::OAuthError, code: "access_denied" },
      { row: "11", name: "the clock passes expires_at while pending",
        authorization: { expires_in: 12 },
        polls: -> { [oauth_error("authorization_pending"), oauth_error("authorization_pending")] },
        events: [[:wait, 5], :poll, [:wait, 5], :poll],
        error: Keycardai::OAuth::OAuthError, code: "expired_token", status: nil },
      { row: "12", name: "expired_token from the server",
        polls: -> { [oauth_error("expired_token")] },
        events: [[:wait, 5], :poll],
        error: Keycardai::OAuth::OAuthError, code: "expired_token", status: 400 },
      { row: "12", name: "invalid_grant from the server",
        polls: -> { [oauth_error("invalid_grant")] },
        events: [[:wait, 5], :poll],
        error: Keycardai::OAuth::OAuthError, code: "invalid_grant", status: 400 },
      { row: "13", name: "a network error",
        polls: -> { [network_error] },
        events: [[:wait, 5], :poll],
        error: poll_error, next_interval: 5, cause: Keycardai::OAuth::NetworkError },
      { row: "13", name: "a 5xx",
        polls: -> { [json_response({}, status: 503)] },
        events: [[:wait, 5], :poll],
        error: poll_error, next_interval: 5, cause: Keycardai::OAuth::HTTPError, cause_status: 503 },
      { row: "13", name: "a 5xx with an OAuth error body",
        polls: -> { [oauth_error("temporarily_unavailable", status: 503)] },
        events: [[:wait, 5], :poll],
        error: poll_error, next_interval: 5, cause: Keycardai::OAuth::OAuthError, cause_status: 503 },
      { row: "16", name: "slow_down, then a network error",
        polls: -> { [oauth_error("slow_down"), network_error] },
        events: [[:wait, 5], :poll, [:wait, 10], :poll],
        error: poll_error, next_interval: 10, cause: Keycardai::OAuth::NetworkError },
      { row: "17", name: "a 429",
        polls: -> { [json_response({}, status: 429)] },
        events: [[:wait, 5], :poll],
        error: poll_error, next_interval: 5, cause: Keycardai::OAuth::HTTPError, cause_status: 429 },
      { row: "18", name: "resumed with interval 10 from row 16's error",
        interval: 10,
        polls: -> { [json_response(token_payload)] },
        events: [[:wait, 10], :poll],
        token: true },
      { row: "19", name: "an interval input below authorization.interval",
        interval: 4,
        polls: -> { [] },
        events: [],
        error: Keycardai::OAuth::ConfigurationError },
      { row: "21", name: "an interval longer than the time left before expires_at",
        authorization: { expires_in: 60 }, interval: 61,
        polls: -> { [] },
        events: [],
        error: Keycardai::OAuth::OAuthError, code: "expired_token", status: nil }
    ].each do |example|
      it "#{example[:row]}: #{example[:name]}" do
        http = zone_http(polls: instance_exec(&example[:polls]))
        auth = authorization(**example.fetch(:authorization, {}))
        run = -> { client(http).wait_for_token(auth, interval: example[:interval]) }

        if example[:token]
          token = run.call
          expect(token).to have_attributes(access_token: "at_device", refresh_token: "rt_device",
                                           id_token: "id.token.value")
        else
          expect(&run).to raise_error(example[:error]) { |e|
            expect(e.error).to eq(example[:code]) if example.key?(:code)
            expect(e.status).to eq(example[:status]) if example.key?(:status)
            expect(e.interval).to eq(example[:next_interval]) if example.key?(:next_interval)
            expect(e.cause).to be_an_instance_of(example[:cause]) if example.key?(:cause)
            expect(e.cause.status).to eq(example[:cause_status]) if example.key?(:cause_status)
          }
        end
        expect(events).to eq(example[:events])
      end
    end

    # Cancellation starts 2 seconds into the first wait. A callable is
    # checked every 0.5 seconds of a wait; a deadline ends the wait at the
    # deadline.
    [
      { name: "a cancelled callable", options: ->(start) { { cancelled: -> { clock.now >= start + 2 } } },
        events: [[:wait, 0.5], [:wait, 0.5], [:wait, 0.5], [:wait, 0.5]] },
      { name: "a deadline", options: ->(start) { { deadline: start + 2 } },
        events: [[:wait, 2]] }
    ].each do |example|
      it "14: cancelled during a wait by #{example[:name]}: CancelledError and no request" do
        http = zone_http
        options = instance_exec(clock.now, &example[:options])

        expect { client(http).wait_for_token(authorization, **options) }
          .to raise_error(Keycardai::OAuth::CancelledError)
        expect(events).to eq(example[:events])
        expect(calls_to(http, zone.token_url)).to be_empty
      end
    end

    it "20 (Ruby): cancellation during an in-flight poll lets the poll finish, then sends no further request" do
      cancel = false
      http = zone_http(polls: [lambda {
        cancel = true
        oauth_error("authorization_pending")
      }])

      expect { client(http).wait_for_token(authorization(interval: 1), cancelled: -> { cancel }) }
        .to raise_error(Keycardai::OAuth::CancelledError)
      expect(events).to eq([[:wait, 0.5], [:wait, 0.5], :poll])
    end

    it "15: polls with the device_code of a DeviceAuthorization rebuilt from persisted fields" do
      stored = JSON.dump(authorization.to_h.merge(device_code: "dc_persisted",
                                                  expires_at: authorization.expires_at.iso8601))
      fields = JSON.parse(stored, symbolize_names: true)
      rebuilt = Keycardai::OAuth::DeviceAuthorization.new(**fields, expires_at: Time.iso8601(fields[:expires_at]))
      http = zone_http(polls: [json_response(token_payload)])

      client(http).wait_for_token(rebuilt)

      expect(sole_call(http, zone.token_url).params.to_h["device_code"]).to eq("dc_persisted")
    end
  end

  it "22: a WebIdentity flow signs a new assertion per request with aud set to that request's endpoint" do
    Dir.mktmpdir do |dir|
      credential = Keycardai::OAuth::WebIdentity.new(client_id: "cid", key_id: "device-key", storage_dir: dir)
      http = zone_http(polls: [oauth_error("authorization_pending"), json_response(token_payload)])
      device = client(http, client_id: nil, credential: credential)

      device.wait_for_token(device.request_device_authorization)

      claims = http.calls.select { |call| call.verb == :post }.map do |call|
        decode_jwt_part(call.params.to_h.fetch("client_assertion").split(".")[1])
      end
      expect(claims.map { |claim| claim["aud"] })
        .to eq([zone.device_authorization_url, zone.token_url, zone.token_url])
      expect(claims.map { |claim| claim["jti"] }.uniq.size).to eq(3)
    end
  end

  it "24: a token for two resources comes back with no resource association, even when the response names one" do
    http = zone_http(polls: [json_response(token_payload.merge("resource" => "https://a.acme.test"))])
    device = client(http)

    device.request_device_authorization(resources: ["https://a.acme.test", "https://b.acme.test"])
    token = device.wait_for_token(authorization)

    expect(token.access_token).to eq("at_device")
    expect(Keycardai::OAuth::TokenResponse.members).not_to include(:resource)
    expect(token.raw["resource"]).to eq("https://a.acme.test")
  end

  describe "client setup" do
    it "uses pre-discovered metadata without a discovery request" do
      metadata = Keycardai::OAuth::Discovery.parse_metadata(zone.issuer, JSON.dump(zone.metadata(device: true)))
      http = zone_http

      described_class.new(metadata: metadata, client_id: "cid", http_client: http, clock: clock)
                     .request_device_authorization

      expect(http.requests).to eq([zone.device_authorization_url])
    end

    it "discovers once and reuses the metadata within discovery_ttl" do
      http = zone_http(polls: [json_response(token_payload)])
      device = client(http)

      device.request_device_authorization
      device.poll_token(authorization)

      expect(http.request_count(zone.metadata_url)).to eq(1)
    end

    it "rejects an issuer that differs from the metadata's issuer" do
      metadata = Keycardai::OAuth::Discovery.parse_metadata(zone.issuer, JSON.dump(zone.metadata(device: true)))

      expect { described_class.new(issuer: "https://other.test", metadata: metadata, client_id: "cid") }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /does not match/)
    end
  end
end
