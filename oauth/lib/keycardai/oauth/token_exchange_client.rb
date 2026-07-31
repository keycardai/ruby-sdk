# frozen_string_literal: true

module Keycardai
  module OAuth
    # RFC 8693 token exchange: swap a subject token for a fresh token scoped
    # to a downstream resource, the core delegation primitive. Also exposes
    # the impersonation convenience, a substitute-user exchange where the
    # authorization server derives the acting party from client
    # authentication.
    #
    # The token endpoint is discovered from the issuer on first use and
    # cached. Requests do not retry transparently.
    class TokenExchangeClient
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

      # Exchange a subject token (RFC 8693).
      #
      # @param subject_token [String] the token being exchanged
      # @param subject_token_type [String] type of the subject token
      # @param resource [String, nil] RFC 8707 target resource
      # @param audience [String, nil] target audience (alternative to resource)
      # @param scope [String, nil] space-separated scopes for the issued token
      # @param requested_token_type [String, nil]
      # @param actor_token [String, nil] the acting party's token, for explicit
      #   delegation; requires actor_token_type
      # @param actor_token_type [String, nil]
      # @param client_assertion [String, nil] client-authentication assertion,
      #   form-encoded in the body
      # @param client_assertion_type [String, nil]
      # @return [TokenResponse]
      # @raise [OAuthError] an RFC 6749 §5.2 error response (invalid_grant,
      #   invalid_target, invalid_scope, unauthorized_client, ...)
      # @raise [HTTPError, ProtocolError, NetworkError]
      def exchange_token(subject_token:, subject_token_type: TokenType::ACCESS_TOKEN, resource: nil,
                         audience: nil, scope: nil, requested_token_type: nil, actor_token: nil,
                         actor_token_type: nil, client_assertion: nil, client_assertion_type: nil)
        raise ArgumentError, "actor_token_type is required when actor_token is set" if actor_token && !actor_token_type

        post_token_request(
          "grant_type" => GrantType::TOKEN_EXCHANGE,
          "subject_token" => subject_token,
          "subject_token_type" => subject_token_type,
          "resource" => resource,
          "audience" => audience,
          "scope" => scope,
          "requested_token_type" => requested_token_type,
          "actor_token" => actor_token,
          "actor_token_type" => actor_token_type,
          "client_assertion" => client_assertion,
          "client_assertion_type" => client_assertion_type
        )
      end

      # Impersonate a named user: a substitute-user token exchange for
      # privileged operations performed on the user's behalf. No actor token
      # is sent; the authorization server derives the acting party from client
      # authentication and records it in the issued token's act chain.
      #
      # @param user_identifier [String] the target user (becomes sub)
      # @param resource [String] target resource for the issued token
      # @param scope [String, nil] space-separated scopes
      # @return [TokenResponse]
      # @raise [OAuthError] invalid_grant (unknown user), unauthorized_client
      #   (impersonation not permitted), and all token-exchange errors
      def impersonate(user_identifier:, resource:, scope: nil)
        raise ArgumentError, "resource must be a non-empty string" if resource.nil? || resource.empty?

        exchange_token(
          subject_token: OAuth.build_substitute_user_token(user_identifier),
          subject_token_type: TokenType::SUBSTITUTE_USER,
          resource: resource,
          scope: scope
        )
      end
    end
  end
end
