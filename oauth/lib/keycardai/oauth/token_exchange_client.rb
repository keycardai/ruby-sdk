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
      # @param credential [Object, nil] an application credential (ClientSecret,
      #   WebIdentity, WorkloadIdentity); exclusive with client_id/client_secret
      # @param client_id [String, nil] shared-secret client id (HTTP Basic)
      # @param client_secret [String, nil] shared-secret client secret;
      #   provide both or neither
      # @param http_client [#get, #post_form] pluggable transport
      # @param timeout [Numeric, nil] request timeout in seconds
      # @raise [ConfigurationError] when only one of client_id/client_secret is
      #   given, or a credential is combined with a raw pair
      def initialize(issuer:, credential: nil, client_id: nil, client_secret: nil,
                     http_client: HTTP::NetHTTPClient.new, timeout: nil)
        initialize_token_client(issuer: issuer, credential: credential, client_id: client_id,
                                client_secret: client_secret, http_client: http_client, timeout: timeout)
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
      # @param issuer [String, nil] per-call zone selection: resolves the zone's
      #   token endpoint and, for a multi-zone credential, that zone's client
      #   authentication. Defaults to the client's issuer.
      # @return [TokenResponse]
      # @raise [OAuthError] an RFC 6749 §5.2 error response (invalid_grant,
      #   invalid_target, invalid_scope, unauthorized_client, ...)
      # @raise [HTTPError, ProtocolError, NetworkError]
      def exchange_token(subject_token:, subject_token_type: nil, resource: nil,
                         audience: nil, scope: nil, requested_token_type: nil, actor_token: nil,
                         actor_token_type: nil, client_assertion: nil, client_assertion_type: nil,
                         issuer: nil)
        raise ArgumentError, "actor_token_type is required when actor_token is set" if actor_token && !actor_token_type

        target = issuer || @issuer
        overrides = {
          "subject_token_type" => subject_token_type,
          "resource" => resource,
          "audience" => audience,
          "scope" => scope,
          "requested_token_type" => requested_token_type,
          "actor_token" => actor_token,
          "actor_token_type" => actor_token_type,
          "client_assertion" => client_assertion,
          "client_assertion_type" => client_assertion_type
        }.compact
        post_token_request(base_exchange_params(subject_token, target).merge(overrides), issuer: target)
      end

      # Impersonate a named user: a substitute-user token exchange for
      # privileged operations performed on the user's behalf. No actor token
      # is sent; the authorization server derives the acting party from client
      # authentication and records it in the issued token's act chain.
      #
      # @param user_identifier [String] the target user (becomes sub)
      # @param resource [String] target resource for the issued token
      # @param scope [String, nil] space-separated scopes
      # @param issuer [String, nil] per-call zone selection
      # @return [TokenResponse]
      # @raise [OAuthError] invalid_grant (unknown user), unauthorized_client
      #   (impersonation not permitted), and all token-exchange errors
      def impersonate(user_identifier:, resource:, scope: nil, issuer: nil)
        raise ArgumentError, "resource must be a non-empty string" if resource.nil? || resource.empty?

        exchange_token(
          subject_token: OAuth.build_substitute_user_token(user_identifier),
          subject_token_type: TokenType::SUBSTITUTE_USER,
          resource: resource,
          scope: scope,
          issuer: issuer
        )
      end

      private

      # The base exchange parameters: built by the credential when one is
      # configured (it supplies assertion fields and defaults), otherwise the
      # bare RFC 8693 defaults. Caller-supplied fields are merged on top.
      def base_exchange_params(subject_token, issuer)
        if @credential
          @credential.prepare_token_exchange_request(subject_token: subject_token,
                                                     token_endpoint: token_endpoint(issuer), issuer: issuer)
        else
          {
            "grant_type" => GrantType::TOKEN_EXCHANGE,
            "subject_token" => subject_token,
            "subject_token_type" => TokenType::ACCESS_TOKEN
          }
        end
      end
    end
  end
end
