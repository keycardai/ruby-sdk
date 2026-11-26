# frozen_string_literal: true

module Keycardai
  module OAuth
    # OAuth 2.0 client_credentials grant (RFC 6749 §4.4): autonomous workload
    # authentication. The client requests a token for itself, with no user in
    # the loop, and authenticates with a shared secret (HTTP Basic) or a
    # client assertion carried on the request.
    #
    # The token endpoint is discovered from the issuer on first use and
    # cached for discovery_ttl; a failed discovery is not cached. Requests do
    # not retry transparently.
    class ClientCredentialsClient
      include TokenRequests

      # @param issuer [String] the zone's issuer URL
      # @param credential [#client_authentication, nil] provides client authentication;
      #   exclusive with client_id/client_secret
      # @param client_id [String, nil] shared-secret client id (HTTP Basic)
      # @param client_secret [String, nil] shared-secret client secret;
      #   provide both or neither
      # @param http_client [#get, #post_form] pluggable transport
      # @param timeout [Numeric, nil] request timeout in seconds
      # @param discovery_ttl [Numeric] token-endpoint cache lifetime in seconds
      # @param clock [#call] returns the current Time; override in tests
      # @raise [ConfigurationError] when only one of client_id/client_secret is
      #   given, a credential is combined with a raw pair, or the credential
      #   does not provide client authentication
      def initialize(issuer:, credential: nil, client_id: nil, client_secret: nil,
                     http_client: HTTP::NetHTTPClient.new, timeout: nil,
                     discovery_ttl: TokenRequests::DEFAULT_DISCOVERY_TTL, clock: MetadataRetry::WALL_CLOCK)
        initialize_token_client(issuer: issuer, credential: credential, client_id: client_id,
                                client_secret: client_secret, http_client: http_client, timeout: timeout,
                                discovery_ttl: discovery_ttl, clock: clock)
        return unless credential && !credential.respond_to?(:client_authentication)

        raise ConfigurationError, "#{credential.class} does not provide client authentication"
      end

      # Request a token for the client itself.
      #
      # @param scope [String, nil] space-separated scopes for the token
      # @param resource [String, nil] RFC 8707 resource indicator
      # @param client_assertion [String, nil] client-authentication assertion,
      #   form-encoded in the body in place of configured client authentication
      # @param client_assertion_type [String, nil]
      # @param client_id [String, nil] the application credential the
      #   assertion authenticates as, form-encoded beside client_assertion;
      #   never sent with HTTP Basic
      # @return [TokenResponse]
      # @raise [OAuthError] an RFC 6749 §5.2 error response (invalid_client,
      #   invalid_scope, ...)
      # @raise [HTTPError, ProtocolError, NetworkError]
      def request_token(scope: nil, resource: nil, client_assertion: nil, client_assertion_type: nil,
                        client_id: nil, issuer: nil)
        post_credentials(
          {
            "grant_type" => GrantType::CLIENT_CREDENTIALS,
            "scope" => scope,
            "resource" => resource,
            "client_assertion" => client_assertion,
            "client_assertion_type" => client_assertion_type,
            "client_id" => client_id
          },
          issuer || @issuer
        )
      end

      private

      def post_credentials(params, issuer)
        if params["client_assertion"] || !@credential
          return post_token_request(params, issuer: issuer, authorization: nil)
        end
        # A ClientSecret resolves its Basic header without the token endpoint,
        # so an unconfigured zone fails before any discovery request.
        return post_with_header(params, issuer) if @credential.is_a?(ClientSecret)

        post_authenticated_credentials(params, issuer)
      end

      def post_authenticated_credentials(params, issuer)
        reject_request_client_fields(params)
        endpoint = token_endpoint(issuer)
        auth = @credential.client_authentication(issuer: issuer, endpoint: endpoint)
        form = params.merge(auth.params)
        post_token_form(endpoint, form, { "Accept" => "application/json" }.merge(auth.headers))
      end

      def post_with_header(params, issuer)
        authorization = @credential.authorization_header(issuer: issuer)
        reject_body_client_id(params) if authorization
        post_token_request(params, issuer: issuer, authorization: authorization)
      end

      def reject_body_client_id(params)
        return unless params["client_id"]

        raise ConfigurationError, "client_id is sent beside client_assertion, not with HTTP Basic"
      end

      # The configured credential supplies client_id and client_assertion_type,
      # so a request value would be dropped or overridden: fail instead.
      def reject_request_client_fields(params)
        return unless params["client_id"] || params["client_assertion_type"]

        raise ConfigurationError, "client_id and client_assertion_type are sent only beside a request client_assertion"
      end
    end
  end
end
