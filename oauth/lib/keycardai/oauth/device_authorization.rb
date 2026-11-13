# frozen_string_literal: true

require "json"
require "uri"

module Keycardai
  module OAuth
    # The device authorization response (RFC 8628 §3.2), with +expires_at+
    # computed from the client's clock when the response arrived. A plain
    # value: the caller may persist its fields and rebuild it in another
    # process that authenticates as the same client.
    #
    # NEVER show +device_code+ to the person. Show +verification_uri_complete+
    # when it is set, and +verification_uri+ otherwise. Always show
    # +user_code+ too, so the person can compare it with the confirmation page.
    DeviceAuthorization = Data.define(
      :device_code, :user_code, :verification_uri, :verification_uri_complete, :expires_in, :interval, :expires_at
    ) do
      # @param device_code [String]
      # @param user_code [String]
      # @param verification_uri [String]
      # @param expires_in [Integer] seconds
      # @param expires_at [Time]
      # @param verification_uri_complete [String, nil]
      # @param interval [Integer] minimum seconds between polls
      def initialize(device_code:, user_code:, verification_uri:, expires_in:, expires_at:,
                     verification_uri_complete: nil, interval: DeviceAuthorizationClient::DEFAULT_INTERVAL)
        super
      end

      # Parse a 2xx device authorization response.
      #
      # @param response [HTTP::Response]
      # @param received_at [Time] the time the response arrived
      # @return [DeviceAuthorization]
      # @raise [ProtocolError] code invalid_response when the body does not
      #   decompress or is not a JSON object, a required field is missing,
      #   or interval is not a positive integer
      def self.from_response(response, received_at:)
        if response.body_error
          raise ProtocolError.new("device authorization response body does not decompress: " \
                                  "#{response.body_error.class}", code: "invalid_response"),
                cause: response.body_error
        end
        document = parse_document(response.body)
        validate(document)

        new(device_code: document["device_code"], user_code: document["user_code"],
            verification_uri: document["verification_uri"],
            verification_uri_complete: document["verification_uri_complete"],
            expires_in: document["expires_in"], expires_at: received_at + document["expires_in"],
            interval: document.fetch("interval", DeviceAuthorizationClient::DEFAULT_INTERVAL))
      end

      def self.parse_document(body)
        document = JSON.parse(body)
        invalid_response("device authorization response is not a JSON object") unless document.is_a?(Hash)
        document
      rescue JSON::ParserError
        invalid_response("device authorization response is not valid JSON")
      end

      def self.validate(document)
        invalid = invalid_fields(document)
        invalid_response("device authorization response lacks a valid #{invalid.join(", ")}") unless invalid.empty?
        return if positive_integer?(document.fetch("interval", DeviceAuthorizationClient::DEFAULT_INTERVAL))

        invalid_response("device authorization response has an interval that is not a positive integer: " \
                         "#{document["interval"].inspect}")
      end

      def self.invalid_fields(document)
        invalid = %w[device_code user_code verification_uri].reject do |field|
          document[field].is_a?(String) && !document[field].empty?
        end
        invalid << "expires_in" unless positive_integer?(document["expires_in"])
        complete = document["verification_uri_complete"]
        invalid << "verification_uri_complete" unless complete.nil? || complete.is_a?(String)
        invalid
      end

      def self.positive_integer?(value)
        value.is_a?(Integer) && value.positive?
      end

      def self.invalid_response(message)
        raise ProtocolError.new(message, code: "invalid_response")
      end

      private_class_method :parse_document, :validate, :invalid_fields, :positive_integer?, :invalid_response
    end

    # OAuth 2.0 device authorization grant (RFC 8628), from the device's side.
    # The device asks the zone for a device code and a user code, the caller
    # shows the user code to a person, and the device polls the token endpoint
    # until the person approves or denies the request.
    #
    # Every request authenticates the same way: with a credential's
    # client_authentication, or as a public client that sends client_id in
    # the body. The client reads device_authorization_endpoint and
    # token_endpoint from the metadata passed in, or from discovery. It does
    # not keep state between operations, except the discovery cache.
    class DeviceAuthorizationClient
      # Poll interval, in seconds, when the response omits one (RFC 8628 §3.2).
      DEFAULT_INTERVAL = 5
      # Seconds added to the interval on each slow_down (RFC 8628 §3.5).
      SLOW_DOWN_INCREMENT = 5
      # Longest sleep, in seconds, between two calls of a +cancelled+ callable
      # during a wait.
      CANCELLATION_CHECK_INTERVAL = 0.5

      # @param issuer [String, nil] the zone's issuer URL; required unless
      #   metadata is given
      # @param metadata [AuthorizationServerMetadata, nil] pre-discovered
      #   metadata; no discovery request is made
      # @param credential [#client_authentication, nil] authenticates every
      #   request; exclusive with client_id
      # @param client_id [String, nil] public client; sent in every body
      # @param http_client [#get, #post_form] pluggable transport
      # @param timeout [Numeric, nil] per-request timeout in seconds, for
      #   discovery, the device authorization request, and each poll. nil
      #   uses the transport's default, 10 seconds for NetHTTPClient.
      # @param clock [#call] returns the current Time; read for expires_at,
      #   the poll waits, and the discovery cache
      # @param sleep [#call] waits the given number of seconds. Inject fakes
      #   for clock and sleep in tests so the poll loop runs without real
      #   delays.
      # @param discovery_ttl [Numeric] metadata cache lifetime in seconds,
      #   0 or more
      # @raise [ConfigurationError] not exactly one of credential and
      #   client_id, a credential without client_authentication, no issuer
      #   or metadata, an issuer that differs from the metadata's, a clock or
      #   sleep that does not respond to call, a timeout that is not
      #   positive, or a negative discovery_ttl
      def initialize(issuer: nil, metadata: nil, credential: nil, client_id: nil,
                     http_client: HTTP::NetHTTPClient.new, timeout: nil, clock: -> { Time.now },
                     sleep: ->(seconds) { Kernel.sleep(seconds) },
                     discovery_ttl: TokenRequests::DEFAULT_DISCOVERY_TTL)
        ClientAuth.validate(credential: credential, client_id: client_id)
        validate_options(timeout, clock, sleep, discovery_ttl)
        @issuer = resolve_issuer(issuer, metadata)
        @credential = credential
        @client_id = client_id
        @http_client = http_client
        @timeout = timeout
        @clock = clock
        @sleep = sleep
        @endpoints = DeviceEndpoints.new(issuer: @issuer, metadata: metadata, http_client: http_client,
                                         timeout: timeout, clock: clock, ttl: discovery_ttl)
      end

      # Ask the zone for a device code and a user code (RFC 8628 §3.1).
      #
      # @param scopes [Array<String>] sent as one space-joined scope
      # @param resources [Array<String>] RFC 8707 resource indicators, one
      #   resource parameter per entry
      # @return [DeviceAuthorization]
      # @raise [ConfigurationError] the metadata has no
      #   device_authorization_endpoint, or it is not an http or https URL;
      #   no request is sent to it
      # @raise [ProtocolError] code invalid_response when the response lacks
      #   device_code, user_code, verification_uri, or expires_in, has an
      #   interval that is not a positive integer, or has a body that does
      #   not decompress
      # @raise [OAuthError] invalid_client, unauthorized_client,
      #   invalid_target, invalid_scope, ...
      # @raise [HTTPError, NetworkError]
      # @raise [ProtocolError, ConfigurationError] from discovery, as
      #   fetch_authorization_server_metadata raises them
      def request_device_authorization(scopes: [], resources: [])
        endpoint = @endpoints.url(:device_authorization_endpoint)
        params = []
        params << ["scope", Array(scopes).join(" ")] unless Array(scopes).empty?
        params.concat(Array(resources).map { |resource| ["resource", resource] })
        response = post(endpoint, params)
        raise TokenRequests.error_for(response, endpoint_name: "device authorization endpoint") unless response.success?

        DeviceAuthorization.from_response(response, received_at: @clock.call)
      end

      # Poll the token endpoint once with the authorization's device_code.
      #
      # If you call poll_token in a loop, wait at least
      # authorization.interval between polls, add 5 seconds after
      # slow_down, and wait longer after a network error (RFC 8628 §3.5).
      #
      # @param authorization [DeviceAuthorization]
      # @return [TokenResponse] once the person has approved
      # @raise [ConfigurationError] the authorization has no device_code, or
      #   the metadata has no token_endpoint or it is not an http or https
      #   URL; no request is sent
      # @raise [OAuthError] the server's code, including authorization_pending
      #   and slow_down
      # @raise [ProtocolError] code invalid_response for a malformed 2xx,
      #   including a body that does not decompress
      # @raise [HTTPError, NetworkError]
      # @raise [ProtocolError, ConfigurationError] from discovery, as
      #   fetch_authorization_server_metadata raises them
      def poll_token(authorization)
        validate_authorization(authorization)
        TokenRequests.parse_response(post(@endpoints.url(:token_endpoint), poll_params(authorization)))
      end

      # Poll until the person approves or denies the request (RFC 8628 §3.5).
      #
      # The loop waits the interval before each poll, including the first.
      # On authorization_pending it polls again. On slow_down it adds 5
      # seconds to the interval for this and every later poll. Any other
      # OAuth error stops the loop and is raised as is. A network error, a
      # 5xx, or a 429 stops the loop with a DevicePollError, and the loop
      # does not repeat that poll. Any other failure, such as the
      # credential's, is raised as is. If the next poll would start after
      # expires_at, it raises OAuthError expired_token without waiting or
      # sending it.
      #
      # Cancellation: the loop calls +cancelled+ and compares +deadline+ with
      # the clock before each request and during each wait. It raises
      # CancelledError once either reports cancellation, and then does not
      # call the credential or send another request. A request in flight is
      # not interrupted. It ends with a response or at the request timeout.
      #
      # When the device authorization request named more than one resource,
      # the token is not for any one of them, even if the response names one.
      # NEVER store it as the token for a single resource. To get a token for
      # one resource, call Keycardai::OAuth.refresh_authorization with
      # resources: [that_resource].
      #
      # @param authorization [DeviceAuthorization]
      # @param interval [Integer, nil] the wait before the first poll and the
      #   starting interval, in seconds. Defaults to authorization.interval.
      #   Pass DevicePollError#interval to resume a stopped loop.
      # @param cancelled [#call, nil] returns true once the caller cancels;
      #   called at least every CANCELLATION_CHECK_INTERVAL seconds of a wait
      # @param deadline [Time, nil] cancel once the clock reaches it
      # @return [TokenResponse]
      # @raise [ConfigurationError] an interval that is not a positive integer
      #   or is below authorization.interval, an authorization without
      #   device_code, expires_at, or a positive integer interval, a
      #   cancelled that does not respond to call, a deadline that is not a
      #   Time, or a bad token_endpoint; no request is sent
      # @raise [OAuthError] expired_token, access_denied, invalid_grant, ...
      #   An expired_token the loop raises without a request has a nil status.
      # @raise [DevicePollError] a poll failed with a network error, a 5xx, or
      #   a 429
      # @raise [CancelledError]
      def wait_for_token(authorization, interval: nil, cancelled: nil, deadline: nil)
        interval = starting_interval(authorization, interval)
        cancellation = DeviceCancellation.new(cancelled: cancelled, deadline: deadline, clock: @clock, sleep: @sleep)
        cancellation.check
        endpoint = @endpoints.url(:token_endpoint)
        check_expiry(authorization, interval)
        loop do
          cancellation.wait(interval)
          token, interval = poll_step(authorization, endpoint, interval)
          return token if token

          check_expiry(authorization, interval)
        end
      end

      private

      def validate_options(timeout, clock, sleep, discovery_ttl)
        raise ConfigurationError, "clock must respond to call" unless clock.respond_to?(:call)
        raise ConfigurationError, "sleep must respond to call" unless sleep.respond_to?(:call)
        unless timeout.nil? || positive_number?(timeout)
          raise ConfigurationError, "timeout #{timeout.inspect} is not a positive number of seconds"
        end
        return if discovery_ttl.is_a?(Numeric) && !discovery_ttl.negative?

        raise ConfigurationError, "discovery_ttl #{discovery_ttl.inspect} is not 0 or more seconds"
      end

      def resolve_issuer(issuer, metadata)
        if metadata.nil?
          raise ConfigurationError, "provide an issuer or metadata" if issuer.nil?

          return issuer
        end
        raise ConfigurationError, "the metadata has no issuer" unless metadata.issuer.is_a?(String)
        return issuer || metadata.issuer if issuer.nil? || issuer.chomp("/") == metadata.issuer.chomp("/")

        raise ConfigurationError, "issuer #{issuer} does not match the metadata issuer #{metadata.issuer}"
      end

      def validate_authorization(authorization)
        code = authorization.device_code if authorization.respond_to?(:device_code)
        return if code.is_a?(String) && !code.empty?

        raise ConfigurationError, "the device authorization has no device_code"
      end

      def poll_params(authorization)
        [["grant_type", GrantType::DEVICE_CODE], ["device_code", authorization.device_code]]
      end

      def post(endpoint, params)
        params, headers = authenticate(endpoint, params)
        @http_client.post_form(endpoint, params, headers: headers, timeout: @timeout)
      end

      def authenticate(endpoint, params)
        ClientAuth.apply(params, { "Accept" => "application/json" }, issuer: @issuer, endpoint: endpoint,
                                                                     credential: @credential, client_id: @client_id)
      end

      def starting_interval(authorization, interval)
        validate_authorization(authorization)
        unless authorization.expires_at.is_a?(Time) && positive_integer?(authorization.interval)
          raise ConfigurationError, "the device authorization needs an expires_at Time and a positive integer interval"
        end
        return authorization.interval if interval.nil?
        unless positive_integer?(interval)
          raise ConfigurationError, "interval #{interval.inspect} is not a positive integer"
        end
        return interval if interval >= authorization.interval

        raise ConfigurationError,
              "interval #{interval.inspect} is below the device authorization's interval #{authorization.interval}"
      end

      def positive_integer?(value)
        value.is_a?(Integer) && value.positive?
      end

      def positive_number?(value)
        value.is_a?(Numeric) && value.positive?
      end

      def check_expiry(authorization, interval)
        return if @clock.call + interval <= authorization.expires_at

        raise OAuthError.new("the device code expires before the next poll", error: "expired_token", status: nil)
      end

      # One poll. Returns the token, or nil and the interval for the next
      # poll. The credential is called outside every rescue, so its failure
      # is raised as is.
      def poll_step(authorization, endpoint, interval)
        params, headers = authenticate(endpoint, poll_params(authorization))
        response = send_poll(endpoint, params, headers, interval)
        begin
          [TokenRequests.parse_response(response), interval]
        rescue HTTPError => e
          poll_error(e, interval)
        end
      end

      def send_poll(endpoint, params, headers, interval)
        @http_client.post_form(endpoint, params, headers: headers, timeout: @timeout)
      rescue NetworkError => e
        # RFC 8628 §3.5: wait longer after a connection timeout.
        raise DevicePollError.new("device token poll failed: #{e.message}", interval: interval * 2)
      end

      # The next step after a poll that raised +error+: poll again, or stop.
      def poll_error(error, interval)
        if error.status == 429 || error.status.to_i >= 500
          raise DevicePollError.new("device token poll failed: #{error.message}", interval: interval)
        end
        raise error unless error.is_a?(OAuthError)

        case error.error
        when "authorization_pending" then [nil, interval]
        when "slow_down" then [nil, interval + SLOW_DOWN_INCREMENT]
        else raise error
        end
      end
    end

    # The device grant's two endpoints, from pre-discovered metadata or from
    # discovery. Discovered metadata is cached for +ttl+ seconds when both
    # endpoints are http or https URLs. Otherwise it is not cached, and the
    # next call fetches it again.
    class DeviceEndpoints
      ENDPOINTS = %i[device_authorization_endpoint token_endpoint].freeze

      def initialize(issuer:, metadata:, http_client:, timeout:, clock:, ttl:)
        @issuer = issuer
        @metadata = metadata
        @http_client = http_client
        @timeout = timeout
        @clock = clock
        @ttl = ttl
        @discovered = nil
        @discovered_at = nil
        @mutex = Mutex.new
      end

      # The URL of one endpoint from the metadata.
      #
      # @raise [ConfigurationError] the endpoint is missing or is not an http
      #   or https URL
      def url(name)
        url = metadata.public_send(name)
        raise ConfigurationError, "metadata for #{@issuer} has no #{name}" if url.nil? || url == ""
        return url if http_url?(url)

        raise ConfigurationError, "#{name} #{url.inspect} is not an http or https URL"
      end

      def http_url?(url)
        return false unless url.is_a?(String)

        uri = URI.parse(url)
        uri.is_a?(URI::HTTP) && !uri.host.to_s.empty?
      rescue URI::InvalidURIError
        false
      end

      private

      def metadata
        return @metadata if @metadata

        @mutex.synchronize do
          return @discovered if @discovered && @clock.call - @discovered_at <= @ttl

          fetched = OAuth.fetch_authorization_server_metadata(@issuer, http_client: @http_client, timeout: @timeout)
          if ENDPOINTS.all? { |name| http_url?(fetched.public_send(name)) }
            @discovered = fetched
            @discovered_at = @clock.call
          end
          fetched
        end
      end
    end
    private_constant :DeviceEndpoints

    # The caller's cancellation for one DeviceAuthorizationClient#wait_for_token
    # call: a +cancelled+ callable, a +deadline+, both, or neither.
    class DeviceCancellation
      def initialize(cancelled:, deadline:, clock:, sleep:)
        raise ConfigurationError, "cancelled must respond to call" unless cancelled.nil? || cancelled.respond_to?(:call)
        raise ConfigurationError, "deadline must be a Time" unless deadline.nil? || deadline.is_a?(Time)

        @cancelled = cancelled
        @deadline = deadline
        @clock = clock
        @sleep = sleep
      end

      # @raise [CancelledError]
      def check
        raise CancelledError, "wait_for_token was cancelled" if @cancelled&.call
        raise CancelledError, "wait_for_token reached its deadline" if @deadline && @clock.call >= @deadline
      end

      # Sleep +seconds+ in steps, checking for cancellation before and after
      # each step. The last check runs right before the poll that follows.
      # The wait counts the seconds passed to sleep, so it ends even when the
      # clock does not advance.
      #
      # @raise [CancelledError]
      def wait(seconds)
        remaining = seconds
        loop do
          check
          break unless remaining.positive?

          step = step(remaining)
          @sleep.call(step)
          remaining -= step
        end
      end

      private

      # The next sleep ends at the wake time, the deadline, or the next
      # call of +cancelled+, whichever comes first.
      def step(remaining)
        steps = [remaining]
        steps << (@deadline - @clock.call) if @deadline
        steps << DeviceAuthorizationClient::CANCELLATION_CHECK_INTERVAL if @cancelled
        steps.min
      end
    end
    private_constant :DeviceCancellation
  end
end
