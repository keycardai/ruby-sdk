# frozen_string_literal: true

require "json"

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
    end

    # The default clock for the device authorization grant: real time and a
    # real sleep. A clock responds to +now+, returning a Time, and
    # +sleep(seconds)+. Inject a fake in tests so the poll loop runs without
    # real delays.
    class SystemClock
      # @return [Time]
      def now
        Time.now
      end

      # @param seconds [Numeric]
      # @return [void]
      def sleep(seconds)
        Kernel.sleep(seconds)
      end
    end

    # OAuth 2.0 device authorization grant (RFC 8628), from the device's side.
    # The device asks the zone for a device code and a user code, the caller
    # shows the user code to a person, and the device polls the token endpoint
    # until the person approves or denies the request.
    #
    # Every request authenticates the same way: with a credential's
    # client_authentication, or as a public client that sends client_id in
    # the body. The client reads device_authorization_endpoint and
    # token_endpoint from discovery, cached for discovery_ttl, or from the
    # metadata passed in. It keeps no state between operations.
    class DeviceAuthorizationClient
      # Poll interval, in seconds, when the response omits one (RFC 8628 §3.2).
      DEFAULT_INTERVAL = 5
      # Seconds added to the interval on each slow_down (RFC 8628 §3.5).
      SLOW_DOWN_INCREMENT = 5
      # Longest sleep, in seconds, between two calls of a +cancelled+ callable
      # during a wait.
      CANCELLATION_CHECK_INTERVAL = 0.5

      REQUIRED_FIELDS = %w[device_code user_code verification_uri].freeze
      private_constant :REQUIRED_FIELDS

      # @param issuer [String, nil] the zone's issuer URL; required unless
      #   metadata is given
      # @param metadata [AuthorizationServerMetadata, nil] pre-discovered
      #   metadata; no discovery request is made
      # @param credential [#client_authentication, nil] authenticates every
      #   request; exclusive with client_id
      # @param client_id [String, nil] public client; sent in every body
      # @param http_client [#get, #post_form] pluggable transport
      # @param timeout [Numeric, nil] per-request timeout in seconds. It
      #   bounds each request, not the wait between polls.
      # @param clock [#now, #sleep] time source for expires_at and the poll
      #   waits
      # @param discovery_ttl [Numeric] metadata cache lifetime in seconds
      # @raise [ConfigurationError] not exactly one of credential and
      #   client_id, a credential without client_authentication, no issuer
      #   or metadata, or an issuer that differs from the metadata's
      def initialize(issuer: nil, metadata: nil, credential: nil, client_id: nil,
                     http_client: HTTP::NetHTTPClient.new, timeout: nil, clock: SystemClock.new,
                     discovery_ttl: TokenRequests::DEFAULT_DISCOVERY_TTL)
        ClientAuth.validate(credential: credential, client_id: client_id)
        @issuer = resolve_issuer(issuer, metadata)
        @metadata = metadata
        @credential = credential
        @client_id = client_id
        @http_client = http_client
        @timeout = timeout
        @clock = clock
        @discovery_ttl = discovery_ttl
        @discovered = nil
        @discovered_at = nil
        @discovery_mutex = Mutex.new
      end

      # Ask the zone for a device code and a user code (RFC 8628 §3.1).
      #
      # @param scopes [Array<String>] sent as one space-joined scope
      # @param resources [Array<String>] RFC 8707 resource indicators, one
      #   resource parameter per entry
      # @return [DeviceAuthorization]
      # @raise [ConfigurationError] the metadata has no
      #   device_authorization_endpoint; no request is sent to it
      # @raise [ProtocolError] code invalid_response when the response lacks
      #   device_code, user_code, verification_uri, or expires_in
      # @raise [OAuthError] invalid_client, unauthorized_client,
      #   invalid_target, invalid_scope, ...
      # @raise [HTTPError, NetworkError]
      def request_device_authorization(scopes: [], resources: [])
        endpoint = metadata.device_authorization_endpoint ||
                   raise(ConfigurationError, "#{@issuer} does not advertise a device_authorization_endpoint")

        params = []
        params << ["scope", Array(scopes).join(" ")] unless Array(scopes).empty?
        params.concat(Array(resources).map { |resource| ["resource", resource] })
        response = post(endpoint, params)
        raise TokenRequests.error_for(response, endpoint_name: "device authorization endpoint") unless response.success?

        parse_device_authorization(response.body)
      end

      # Poll the token endpoint once with the authorization's device_code.
      #
      # @param authorization [DeviceAuthorization]
      # @return [TokenResponse] once the person has approved
      # @raise [OAuthError] the server's code, including authorization_pending
      #   and slow_down
      # @raise [HTTPError, ProtocolError, NetworkError]
      def poll_token(authorization)
        params = [["grant_type", GrantType::DEVICE_CODE], ["device_code", authorization.device_code]]
        TokenRequests.parse_response(post(token_endpoint, params))
      end

      # Poll until the person approves or denies the request (RFC 8628 §3.5).
      #
      # The loop waits the interval before each poll, including the first.
      # On authorization_pending it polls again. On slow_down it adds 5
      # seconds to the interval for this and every later poll. Any other
      # OAuth error stops the loop and is raised as is. A network error, a
      # 5xx, or a 429 stops the loop with a DevicePollError. The loop never
      # repeats a failed poll. If the next poll would start after expires_at,
      # it raises OAuthError expired_token without waiting or sending it.
      #
      # Cancellation: the loop calls +cancelled+ and compares +deadline+ with
      # the clock before each request and during each wait, and raises
      # CancelledError once either reports cancellation. A request in flight
      # is not interrupted. It ends with a response or at the request
      # timeout, and then the loop sends no further request.
      #
      # When the device authorization request named more than one resource,
      # the token is not for any one of them, even if the response names one.
      # NEVER store it as the token for a single resource. To get a token for
      # one resource, call refresh_authorization with that resource.
      #
      # @param authorization [DeviceAuthorization]
      # @param interval [Integer, nil] the wait before the first poll and the
      #   starting interval, in seconds. Defaults to authorization.interval.
      #   Pass DevicePollError#interval to resume a stopped loop.
      # @param cancelled [#call, nil] returns true once the caller cancels;
      #   called at least every CANCELLATION_CHECK_INTERVAL seconds of a wait
      # @param deadline [Time, nil] cancel once the clock reaches it
      # @return [TokenResponse]
      # @raise [ConfigurationError] an interval below authorization.interval,
      #   or an authorization without device_code or expires_at; no request
      #   is sent
      # @raise [OAuthError] expired_token, access_denied, invalid_grant, ...
      #   An expired_token the loop raises without a request has a nil status.
      # @raise [DevicePollError] a poll failed with a network error, a 5xx, or
      #   a 429
      # @raise [CancelledError]
      def wait_for_token(authorization, interval: nil, cancelled: nil, deadline: nil)
        interval = starting_interval(authorization, interval)
        cancellation = Cancellation.new(cancelled: cancelled, deadline: deadline, clock: @clock)
        loop do
          raise_expired if @clock.now + interval > authorization.expires_at
          cancellation.wait(interval)
          token, interval = poll_step(authorization, interval)
          return token if token
        end
      end

      private

      def resolve_issuer(issuer, metadata)
        raise ConfigurationError, "provide an issuer or metadata" if issuer.nil? && metadata.nil?
        return issuer || metadata.issuer if issuer.nil? || metadata.nil?
        return issuer if issuer.chomp("/") == metadata.issuer.chomp("/")

        raise ConfigurationError, "issuer #{issuer} does not match the metadata issuer #{metadata.issuer}"
      end

      # Pre-discovered metadata, or discovered metadata cached for
      # discovery_ttl. Only a success is cached.
      def metadata
        return @metadata if @metadata

        @discovery_mutex.synchronize do
          if @discovered.nil? || @clock.now - @discovered_at > @discovery_ttl
            @discovered = OAuth.fetch_authorization_server_metadata(@issuer, http_client: @http_client,
                                                                             timeout: @timeout)
            @discovered_at = @clock.now
          end
          @discovered
        end
      end

      def token_endpoint
        metadata.token_endpoint ||
          raise(ProtocolError.new("metadata for #{@issuer} has no token_endpoint", code: "invalid_metadata"))
      end

      def post(endpoint, params)
        params, headers = ClientAuth.apply(params, { "Accept" => "application/json" },
                                           issuer: @issuer, endpoint: endpoint,
                                           credential: @credential, client_id: @client_id)
        @http_client.post_form(endpoint, params, headers: headers, timeout: @timeout)
      end

      def parse_device_authorization(body)
        document = parse_document(body)
        validate_device_authorization(document)

        DeviceAuthorization.new(
          device_code: document["device_code"], user_code: document["user_code"],
          verification_uri: document["verification_uri"],
          verification_uri_complete: document["verification_uri_complete"],
          expires_in: document["expires_in"], interval: document.fetch("interval", DEFAULT_INTERVAL),
          expires_at: @clock.now + document["expires_in"]
        )
      end

      def validate_device_authorization(document)
        missing = REQUIRED_FIELDS.reject { |field| document[field].is_a?(String) && !document[field].empty? }
        missing << "expires_in" unless positive_integer?(document["expires_in"])
        invalid_response("device authorization response is missing #{missing.join(", ")}") unless missing.empty?
        return if positive_integer?(document.fetch("interval", DEFAULT_INTERVAL))

        invalid_response("device authorization response has an invalid interval")
      end

      def parse_document(body)
        document = JSON.parse(body)
        invalid_response("device authorization response is not a JSON object") unless document.is_a?(Hash)
        document
      rescue JSON::ParserError
        invalid_response("device authorization response is not valid JSON")
      end

      def positive_integer?(value)
        value.is_a?(Integer) && value.positive?
      end

      def invalid_response(message)
        raise ProtocolError.new(message, code: "invalid_response")
      end

      def starting_interval(authorization, interval)
        if authorization.device_code.nil? || authorization.device_code.empty? || authorization.expires_at.nil?
          raise ConfigurationError, "the device authorization needs a device_code and an expires_at"
        end
        return authorization.interval if interval.nil?
        return interval if interval >= authorization.interval

        raise ConfigurationError,
              "interval #{interval} is below the device authorization's interval #{authorization.interval}"
      end

      def raise_expired
        raise OAuthError.new("the device code expires before the next poll", error: "expired_token", status: nil)
      end

      # One poll. Returns the token, or nil and the interval for the next poll.
      def poll_step(authorization, interval)
        [poll_token(authorization), interval]
      rescue NetworkError, HTTPError => e
        raise DevicePollError.new("device token poll failed: #{e.message}", interval: interval) if transient?(e)
        raise unless e.is_a?(OAuthError)

        case e.error
        when "authorization_pending" then [nil, interval]
        when "slow_down" then [nil, interval + SLOW_DOWN_INCREMENT]
        else raise
        end
      end

      def transient?(error)
        return true if error.is_a?(NetworkError)

        error.status == 429 || (error.status.is_a?(Integer) && error.status >= 500)
      end

      # The caller's cancellation for one wait_for_token call: a +cancelled+
      # callable, a +deadline+, both, or neither.
      class Cancellation
        def initialize(cancelled:, deadline:, clock:)
          @cancelled = cancelled
          @deadline = deadline
          @clock = clock
        end

        # Sleep +seconds+ on the clock. Checks for cancellation before and
        # after each sleep, so the check also runs right before the request
        # that follows the wait.
        #
        # @raise [CancelledError]
        def wait(seconds)
          wake = @clock.now + seconds
          loop do
            check
            remaining = wake - @clock.now
            break unless remaining.positive?

            @clock.sleep(step(remaining))
          end
        end

        private

        def check
          raise CancelledError, "wait_for_token was cancelled" if @cancelled&.call
          raise CancelledError, "wait_for_token reached its deadline" if @deadline && @clock.now >= @deadline
        end

        # The next sleep ends at the wake time, the deadline, or the next
        # check of +cancelled+, whichever comes first.
        def step(remaining)
          steps = [remaining]
          steps << (@deadline - @clock.now) if @deadline
          steps << CANCELLATION_CHECK_INTERVAL if @cancelled
          steps.min
        end
      end
      private_constant :Cancellation
    end
  end
end
