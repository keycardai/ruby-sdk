# frozen_string_literal: true

require "json"
require "time"

module Keycardai
  # Resource tokens from the local Keycard agent: the agent token source and
  # the predicates over the agent's refusals.
  module OAuth
    # A resource token source backed by the Keycard agent on this machine: the
    # per-session server +keycard run+ starts for its child, or the
    # +keycard agent+ daemon. The agent brokers the token with the developer's
    # own zone session and asks a human to approve each new request, so the
    # application holds no client secret, refresh token, or session.
    #
    # Construction is inert: nothing is dialled and the socket is not resolved
    # until #resource_token. The socket is resolved on every call (see
    # AgentSocket), so a changed environment takes effect on the next call.
    #
    # Reading +KEYCARD_SOCKET+ and the default-socket variables from +env+ is
    # the second sanctioned environment read in the SDK, beside
    # FileTokenSource's: +keycard run+ generates its socket path per session,
    # so the environment is the only channel that delivers it. Pass +socket:+
    # or +env:+ to keep the process environment out of it.
    #
    # Tokens are not cached here. The agent caches each approved token, and
    # every call sends exactly one IssueToken request.
    class AgentTokenSource
      ISSUE_TOKEN_URL = "http://localhost/keycard.agent.v1.AgentService/IssueToken"
      # Bytes of a non-200 response body parsed for a Connect error.
      ERROR_BODY_LIMIT = 64 * 1024
      # Largest 200 response body accepted; a longer one is an
      # AgentResponseError, not parsed from a prefix.
      BODY_LIMIT = 1 << 20
      # C0 controls and DEL: the token is headed for an Authorization header.
      CONTROL_CHARACTER = /[\x00-\x1f\x7f]/
      # RFC 3339 with up to nine fractional digits, which Time.xmlschema parses
      # exactly but would also accept without an offset.
      RFC3339 = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})\z/i

      # @param socket [String, Pathname, nil] the agent's socket; resolved from
      #   +env+ when nil or empty
      # @param env [#[]] where KEYCARD_SOCKET and the default-socket variables
      #   are read from
      # @param workload [String] name shown in the approval prompt; self-declared
      # @param app_id [String] identifier of the Keycard application the caller
      #   says it acts for, as set on the application; self-declared
      # @param org [String] organization id, for the multi-zone daemon
      # @param zone [String] zone id, set alongside org
      # @param clock [#call] returns the current Time, for +expires_in+
      # @param timeout [Numeric, nil] bound in seconds on each request, from the
      #   dial to the end of the response; nil, the default, waits as long as
      #   the human takes to answer the prompt
      # @param http_client [#post_json, nil] replaces the connection to the
      #   agent, for tests; when nil each call dials the resolved socket
      def initialize(socket: nil, env: ENV, workload: "", app_id: "", org: "", zone: "",
                     clock: -> { Time.now }, timeout: nil, http_client: nil)
        @socket = socket
        @env = env
        @workload = workload
        @app_id = app_id
        @org = org
        @zone = zone
        @clock = clock
        @timeout = timeout
        @http_client = http_client
      end

      # A token for +resource+ carrying +scopes+. Blocks until the agent
      # answers, which on a first request means until the human does.
      #
      # @param resource [String] RFC 8707 resource indicator, sent exactly as given
      # @param scopes [Array<String>] sent exactly as given
      # @return [TokenResponse] +expires_in+ is nil when the agent sent no
      #   expiry; +scope+ is nil unless the agent reported the grant
      # @raise [ConfigurationError] an empty resource, scopes that is not an
      #   Array of Strings, a control character in org or zone, a string that
      #   is not valid UTF-8, or a default socket that cannot be resolved
      # @raise [NetworkError] the socket cannot be reached; names the path
      # @raise [AgentError] the agent refused
      # @raise [AgentResponseError] the agent's 200 response is unusable,
      #   including a body over 1 MiB
      # @raise [HTTPError] a non-200 response that is not a Connect error
      def resource_token(resource:, scopes: [])
        raise ConfigurationError, "resource is required" if resource.nil? || resource.empty?

        validate_request(resource, scopes)
        socket = AgentSocket.resolve(socket: @socket, env: @env)
        response = issue(socket, resource, scopes)
        raise error_for(response) unless response.status == 200

        token_from(response.body)
      end

      # Shows the socket option and the request's self-declared fields. Never
      # shows +env+, which defaults to the whole process environment.
      #
      # @return [String]
      def inspect
        shown = { socket: @socket, workload: @workload, app_id: @app_id, org: @org, zone: @zone }
                .map { |name, value| "#{name}=#{value.inspect}" }
        "#<#{self.class} #{shown.join(", ")}>"
      end
      alias to_s inspect

      # Used by pp.
      def pretty_print(printer)
        printer.text(inspect)
      end

      private

      # org and zone travel as header values, and every string as JSON; a
      # control character or invalid UTF-8 would otherwise escape as
      # ArgumentError or JSON::GeneratorError rather than an SDK error.
      def validate_request(resource, scopes)
        validate_scopes(scopes)
        strings = { "resource" => [resource], "scopes" => scopes, "workload" => [@workload],
                    "app_id" => [@app_id], "org" => [@org], "zone" => [@zone] }
        strings.each do |name, values|
          raise ConfigurationError, "#{name} is not valid UTF-8" unless values.all? { |v| !v.is_a?(String) || utf8?(v) }
        end
        { "org" => @org, "zone" => @zone }.each do |name, value|
          raise ConfigurationError, "#{name} contains a control character" if CONTROL_CHARACTER.match?(value.to_s)
        end
      end

      # A String would otherwise go out as a JSON string where the agent
      # expects an array.
      def validate_scopes(scopes)
        return if scopes.is_a?(Array) && scopes.all?(String)

        raise ConfigurationError, "scopes must be an Array of Strings"
      end

      def utf8?(value)
        value.encode(Encoding::UTF_8).valid_encoding?
      rescue EncodingError
        false
      end

      def issue(socket, resource, scopes)
        client = @http_client || HTTP::UnixSocketClient.new(socket.path)
        client.post_json(ISSUE_TOKEN_URL, request_body(resource, scopes), headers: request_headers,
                                                                          timeout: @timeout)
      rescue HTTP::UnixSocketClient::BodyTooLargeError
        raise body_too_large
      rescue NetworkError => e
        raise NetworkError, unreachable_message(socket, e)
      end

      def body_too_large
        AgentResponseError.new("Keycard agent response body is over #{BODY_LIMIT} bytes")
      end

      def request_body(resource, scopes)
        body = { "resource" => resource, "scopes" => scopes, "workload" => @workload || "" }
        body["appId"] = @app_id unless @app_id.nil? || @app_id.empty?
        body
      end

      def request_headers
        headers = { "Content-Type" => "application/json", "Connect-Protocol-Version" => "1" }
        headers["Keycard-Org"] = @org unless @org.nil? || @org.empty?
        headers["Keycard-Zone"] = @zone unless @zone.nil? || @zone.empty?
        headers
      end

      def unreachable_message(socket, error)
        message = "cannot reach the Keycard agent at #{socket.path} (chosen by #{socket.rule_description}): " \
                  "#{error.message}"
        return message unless socket.rule == :default

        "#{message}; start the agent with `keycard agent start`, or run this process under `keycard run`"
      end

      def error_for(response)
        body = response.body.to_s.byteslice(0, ERROR_BODY_LIMIT)
        payload = parse_json(body)
        code = payload["code"] if payload.is_a?(Hash)
        unless code.is_a?(String) && !code.empty?
          return HTTPError.new("Keycard agent returned HTTP #{response.status}", status: response.status,
                                                                                 body: body)
        end

        message = payload["message"]
        AgentError.new(message.is_a?(String) ? message : "", code: code)
      end

      def token_from(body)
        raise body_too_large if body.bytesize > BODY_LIMIT

        payload = parse_json(body)
        raise AgentResponseError, "Keycard agent response is not a JSON object" unless payload.is_a?(Hash)

        TokenResponse.new(
          access_token: validated_token(payload["token"]), token_type: "Bearer",
          expires_in: expires_in(payload["expiresAt"]), scope: granted_scopes(payload["scopes"]),
          issued_token_type: nil, refresh_token: nil, id_token: nil, raw: payload
        )
      end

      def validated_token(token)
        raise AgentResponseError, "Keycard agent response has no token" unless token.is_a?(String) && !token.empty?
        raise AgentResponseError, "Keycard agent token contains a control character" if CONTROL_CHARACTER.match?(token)

        token
      end

      def expires_in(expires_at)
        return nil if expires_at.nil?
        unless expires_at.is_a?(String) && RFC3339.match?(expires_at)
          raise AgentResponseError, "Keycard agent expiresAt is not an RFC 3339 timestamp"
        end

        [(Time.xmlschema(expires_at) - @clock.call).floor, 0].max
      rescue ArgumentError
        raise AgentResponseError, "Keycard agent expiresAt is not an RFC 3339 timestamp"
      end

      # An absent or empty list means the grant is unknown, so it stays nil
      # rather than falling back to the requested scopes.
      def granted_scopes(scopes)
        return nil if scopes.nil?
        unless scopes.is_a?(Array) && scopes.all?(String)
          raise AgentResponseError, "Keycard agent scopes is not a list of strings"
        end

        scopes unless scopes.empty?
      end

      def parse_json(body)
        JSON.parse(body)
      rescue JSON::ParserError, EncodingError
        nil
      end
    end

    # Whether +error+, or an error in its +cause+ chain, is the agent refusing
    # issuance: the human declined, the prompt expired or failed, the exchange
    # was rejected, or the agent has no session for the org and zone. Do not
    # retry automatically; the agent remembers approvals but not declines, so
    # a retry prompts the human again.
    def self.declined?(error)
      AgentError.find(error)&.code == AgentCode::PERMISSION_DENIED
    end

    # Whether the agent is bounding how often it interrupts the human, or too
    # many prompts are waiting. Back off.
    def self.rate_limited?(error)
      AgentError.find(error)&.code == AgentCode::RESOURCE_EXHAUSTED
    end

    # Whether the agent's host has no way to ask a human. Retrying will not
    # help; fall back to another credential if there is one.
    def self.prompter_unavailable?(error)
      AgentError.find(error)&.code == AgentCode::FAILED_PRECONDITION
    end

    # Whether the developer must act first: sign in, authorize the resource,
    # or repair the zone session. The error's message names the command.
    def self.authorization_required?(error)
      AgentError.find(error)&.code == AgentCode::UNAUTHENTICATED
    end

    # Whether the declared +app_id+ names no application in the zone.
    def self.application_not_found?(error)
      AgentError.find(error)&.code == AgentCode::NOT_FOUND
    end

    # Whether a service behind the agent could not be reached. Transient.
    def self.unavailable?(error)
      AgentError.find(error)&.code == AgentCode::UNAVAILABLE
    end
  end
end
