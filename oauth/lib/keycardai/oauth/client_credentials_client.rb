# frozen_string_literal: true

module Keycardai
  module OAuth
    # OAuth 2.0 client_credentials grant (RFC 6749 §4.4): autonomous workload
    # authentication. The client requests a token for itself, with no user in
    # the loop, and authenticates with a shared secret (HTTP Basic) or a
    # client assertion carried on the request.
    #
    # The token endpoint is discovered from the issuer on first use and
    # cached. Requests do not retry transparently.
    class ClientCredentialsClient
      include TokenRequests

      # @param issuer [String] the zone's issuer URL
      # @param client_id [String, nil] shared-secret client id (HTTP Basic)
      # @param client_secret [String, nil] shared-secret client secret;
      #   provide both or neither
      # @param http_client [#get, #post_form] pluggable transport
      # @param timeout [Numeric, nil] request timeout in seconds
      # @raise [ConfigurationError] when only one of client_id/client_secret is given
      def initialize(issuer:, client_id: nil, client_secret: nil,
                     http_client: HTTP::NetHTTPClient.new, timeout: nil)
        initialize_token_client(issuer: issuer, client_id: client_id, client_secret: client_secret,
                                http_client: http_client, timeout: timeout)
      end

      # Request a token for the client itself.
      #
      # @param scope [String, nil] space-separated scopes for the token
      # @param resource [String, nil] RFC 8707 resource indicator
      # @param client_assertion [String, nil] client-authentication assertion,
      #   form-encoded in the body
      # @param client_assertion_type [String, nil]
      # @return [TokenResponse]
      # @raise [OAuthError] an RFC 6749 §5.2 error response (invalid_client,
      #   invalid_scope, ...)
      # @raise [HTTPError, ProtocolError, NetworkError]
      def request_token(scope: nil, resource: nil, client_assertion: nil, client_assertion_type: nil)
        post_token_request(
          "grant_type" => GrantType::CLIENT_CREDENTIALS,
          "scope" => scope,
          "resource" => resource,
          "client_assertion" => client_assertion,
          "client_assertion_type" => client_assertion_type
        )
      end
    end
  end
end
