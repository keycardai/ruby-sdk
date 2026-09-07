# frozen_string_literal: true

require "json"
require "securerandom"

module Keycardai
  # The A2A delegation client and its result type.
  module A2A
    # The result of a delegated invocation: the target's JSON-RPC result plus
    # the agent card it was discovered through.
    Result = Data.define(:message, :agent_card)

    # Calls another agent on the user's behalf, carrying the user's identity
    # through the hop: discover the target's agent card, exchange the inbound
    # user token for one scoped to the target (RFC 8693; the user stays the
    # subject and the authorization server records this agent in the act
    # chain), and invoke the target's JSON-RPC endpoint with the exchanged
    # token as the bearer credential.
    class DelegationClient
      # @param issuer [String] the zone where exchanges are performed
      # @param credential [Object, nil] this agent's application credential
      # @param client_id [String, nil] shared-secret pair alternative
      # @param client_secret [String, nil]
      # @param http_client [#get, #post_form, #post_json] pluggable transport
      # @param discovery [ServiceDiscovery, nil] card resolution override
      # @param invoke_timeout [Numeric, nil] JSON-RPC call timeout
      # @param protocol_version [String] the A2A generation to speak: PROTOCOL_VERSION
      #   (1.0: SendMessage, A2A-Version header, ROLE_USER roles, untagged text parts)
      #   or LEGACY_PROTOCOL_VERSION (0.3: message/send, X-A2A-Protocol-Version header,
      #   "user" roles, kind-tagged parts). Build the message with A2A.text_message
      #   either way; the client translates it for 0.3.
      # @raise [ArgumentError] protocol_version is neither supported generation
      def initialize(issuer:, credential: nil, client_id: nil, client_secret: nil,
                     http_client: OAuth::HTTP::NetHTTPClient.new, discovery: nil,
                     invoke_timeout: nil, protocol_version: PROTOCOL_VERSION)
        @exchange = OAuth::TokenExchangeClient.new(issuer: issuer, credential: credential,
                                                   client_id: client_id, client_secret: client_secret,
                                                   http_client: http_client)
        @discovery = discovery || ServiceDiscovery.new(http_client: http_client)
        @http_client = http_client
        @invoke_timeout = invoke_timeout
        @wire = Wire.for(protocol_version)
      end

      # Delegate a call to another agent: discover, exchange, invoke.
      #
      # @param target [String] the downstream agent's base URL
      # @param subject_token [String] the inbound user's verified access token
      # @param message [Hash] the A2A SendMessage params (see A2A.text_message)
      # @return [Result] message is the JSON-RPC result as the agent returned it:
      #   for a 1.0 agent an object with a +message+ or +task+ key
      # @raise [ArgumentError] protocol_version is unsupported
      # @raise [DiscoveryError] the agent card cannot be resolved
      # @raise [Keycardai::OAuth::OAuthError] the exchange was rejected
      # @raise [InvocationError] the JSON-RPC call failed
      def invoke(target:, subject_token:, message:)
        card = @discovery.get_card(target)
        token = @exchange.exchange_token(subject_token: subject_token, resource: target.chomp("/"))
        result = post_jsonrpc(jsonrpc_url(target, card), token.access_token, message)
        Result.new(message: result, agent_card: card)
      end

      private

      # The invocation endpoint: read from the card when it names one (a 1.0
      # card's JSONRPC interface or a 0.3 card's url), otherwise derived by
      # convention from the target base URL.
      def jsonrpc_url(target, card)
        @wire.endpoint_from(card) || "#{target.chomp("/")}#{JSONRPC_PATH}"
      end

      def post_jsonrpc(url, access_token, message)
        payload = { "jsonrpc" => "2.0", "id" => SecureRandom.uuid, "method" => @wire.method_name,
                    "params" => @wire.encode_params(message) }
        headers = { "Accept" => "application/json", "Authorization" => "Bearer #{access_token}",
                    @wire.header => @wire.version }
        response = begin
          @http_client.post_json(url, payload, headers: headers, timeout: @invoke_timeout)
        rescue OAuth::NetworkError => e
          raise InvocationError, "invocation of #{url} failed: #{e.message}"
        end
        raise InvocationError, "invocation of #{url} returned HTTP #{response.status}" unless response.success?

        parse_jsonrpc(url, response.body)
      end

      def parse_jsonrpc(url, body)
        document = begin
          JSON.parse(body)
        rescue JSON::ParserError
          raise InvocationError, "invocation of #{url} returned invalid JSON"
        end
        if document["error"]
          raise InvocationError.new("invocation of #{url} returned a JSON-RPC error: #{document["error"]["message"]}",
                                    rpc_error: document["error"])
        end

        document["result"]
      end
    end

    # Build A2A 1.0 SendMessage params carrying one text part, the common case
    # for driving a downstream agent. A client configured for 0.3 translates
    # the role and part shape on the way out.
    #
    # @param text [String]
    # @return [Hash]
    def self.text_message(text)
      {
        "message" => {
          "role" => ROLE_USER,
          "parts" => [{ "text" => text }],
          "messageId" => SecureRandom.uuid
        }
      }
    end
  end
end
