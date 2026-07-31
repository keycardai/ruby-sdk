# frozen_string_literal: true

require "json"

module Keycardai
  module OAuth
    # Shared internals for clients that POST to the token endpoint: lazy
    # endpoint discovery with caching, shared-secret (HTTP Basic) client
    # authentication, and RFC 6749 §5.2 error parsing. Not public API.
    module TokenRequests
      # Parse a token-endpoint response: a TokenResponse on 2xx, a raised
      # typed error otherwise.
      #
      # @param response [HTTP::Response]
      # @return [TokenResponse]
      def self.parse_response(response)
        raise error_for(response) unless response.success?

        document = begin
          JSON.parse(response.body)
        rescue JSON::ParserError
          raise ProtocolError.new("token response is not valid JSON", code: "invalid_response")
        end
        unless document.is_a?(Hash)
          raise ProtocolError.new("token response is not a JSON object",
                                  code: "invalid_response")
        end

        TokenResponse.from_wire(document)
      end

      # RFC 6749 §5.2: an error response carries error / error_description /
      # error_uri. Anything else non-2xx is a plain HTTP error.
      #
      # @param response [HTTP::Response]
      # @return [OAuthError, HTTPError]
      def self.error_for(response)
        payload = begin
          JSON.parse(response.body)
        rescue JSON::ParserError
          nil
        end
        unless payload.is_a?(Hash) && payload["error"].is_a?(String)
          return HTTPError.new("token endpoint returned HTTP #{response.status}",
                               status: response.status, body: response.body)
        end

        OAuthError.new("token endpoint returned #{payload["error"]}",
                       error: payload["error"], error_description: payload["error_description"],
                       error_uri: payload["error_uri"], status: response.status, body: response.body)
      end

      private

      def initialize_token_client(issuer:, credential:, client_id:, client_secret:, http_client:, timeout:)
        validate_client_auth(credential, client_id, client_secret)

        @issuer = issuer
        @credential = credential || (client_id ? ClientSecret.new(client_id, client_secret) : nil)
        @http_client = http_client
        @timeout = timeout
        @token_endpoints = {}
        @token_endpoint_mutex = Mutex.new
      end

      def validate_client_auth(credential, client_id, client_secret)
        if credential && (client_id || client_secret)
          raise ConfigurationError, "provide a credential or a client_id/client_secret pair, not both"
        end
        return unless (client_id.nil? || client_secret.nil?) && client_id != client_secret

        raise ConfigurationError, "client_id and client_secret must be provided together"
      end

      # Discover a zone's token endpoint once and cache it, keyed by issuer
      # so multi-zone clients never reuse another zone's endpoint.
      def token_endpoint(issuer = @issuer)
        @token_endpoint_mutex.synchronize do
          @token_endpoints[issuer] ||= begin
            metadata = OAuth.fetch_authorization_server_metadata(issuer, http_client: @http_client,
                                                                         timeout: @timeout)
            metadata.token_endpoint ||
              raise(ProtocolError.new("metadata for #{issuer} has no token_endpoint", code: "invalid_metadata"))
          end
        end
      end

      def post_token_request(params, issuer: @issuer)
        headers = { "Accept" => "application/json" }
        authorization = @credential&.authorization_header(issuer: issuer)
        headers["Authorization"] = authorization if authorization

        response = @http_client.post_form(token_endpoint(issuer), params.compact, headers: headers,
                                                                                  timeout: @timeout)
        TokenRequests.parse_response(response)
      end
    end
  end
end
