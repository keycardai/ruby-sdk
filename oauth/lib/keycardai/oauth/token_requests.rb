# frozen_string_literal: true

require "json"

module Keycardai
  module OAuth
    # Shared internals for clients that POST to the token endpoint: lazy
    # endpoint discovery with caching, shared-secret (HTTP Basic) client
    # authentication, and RFC 6749 §5.2 error parsing. Not public API.
    module TokenRequests
      private

      def initialize_token_client(issuer:, client_id:, client_secret:, http_client:, timeout:)
        if (client_id.nil? || client_secret.nil?) && client_id != client_secret
          raise ConfigurationError, "client_id and client_secret must be provided together"
        end

        @issuer = issuer
        @client_id = client_id
        @client_secret = client_secret
        @http_client = http_client
        @timeout = timeout
        @token_endpoint = nil
        @token_endpoint_mutex = Mutex.new
      end

      # Discover the zone's token endpoint once and cache it.
      def token_endpoint
        @token_endpoint_mutex.synchronize do
          @token_endpoint ||= begin
            metadata = OAuth.fetch_authorization_server_metadata(@issuer, http_client: @http_client,
                                                                          timeout: @timeout)
            metadata.token_endpoint ||
              raise(ProtocolError.new("metadata for #{@issuer} has no token_endpoint", code: "invalid_metadata"))
          end
        end
      end

      def post_token_request(params)
        headers = { "Accept" => "application/json" }
        headers["Authorization"] = HTTP.basic_authorization(@client_id, @client_secret) if @client_id

        response = @http_client.post_form(token_endpoint, params.compact, headers: headers, timeout: @timeout)
        raise token_error(response) unless response.success?

        TokenResponse.from_wire(parse_token_body(response))
      end

      def parse_token_body(response)
        document = JSON.parse(response.body)
        unless document.is_a?(Hash)
          raise ProtocolError.new("token response is not a JSON object",
                                  code: "invalid_response")
        end

        document
      rescue JSON::ParserError
        raise ProtocolError.new("token response is not valid JSON", code: "invalid_response")
      end

      # RFC 6749 §5.2: an error response carries error / error_description /
      # error_uri. Anything else non-2xx is a plain HTTP error.
      def token_error(response)
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
    end
  end
end
