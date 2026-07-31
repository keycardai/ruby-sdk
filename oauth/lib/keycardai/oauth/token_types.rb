# frozen_string_literal: true

module Keycardai
  module OAuth
    # RFC 8693 token-type URIs, plus the Keycard substitute-user extension.
    module TokenType
      ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
      REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
      ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
      JWT = "urn:ietf:params:oauth:token-type:jwt"
      SUBSTITUTE_USER = "urn:keycard:params:oauth:token-type:substitute-user"
    end

    # OAuth 2.0 grant-type identifiers the SDK speaks.
    module GrantType
      CLIENT_CREDENTIALS = "client_credentials"
      AUTHORIZATION_CODE = "authorization_code"
      TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    end

    # A token issued by the authorization server, the shared response shape of
    # token exchange, client credentials, and the authorization-code exchange.
    # +scope+ is parsed from the space-separated wire value into an array;
    # +token_type+ defaults to "Bearer" when the server omits it. The complete
    # response body is preserved in +raw+.
    TokenResponse = Data.define(
      :access_token, :token_type, :expires_in, :scope, :issued_token_type, :refresh_token, :id_token, :raw
    ) do
      # @param payload [Hash] the parsed token-endpoint response body
      # @return [TokenResponse]
      # @raise [ProtocolError] when the response carries no access token
      def self.from_wire(payload)
        access_token = payload["access_token"]
        unless access_token.is_a?(String) && !access_token.empty?
          raise ProtocolError.new("token response has no access_token", code: "invalid_response")
        end

        new(
          access_token: access_token,
          token_type: payload["token_type"] || "Bearer",
          expires_in: payload["expires_in"],
          scope: payload["scope"]&.split,
          issued_token_type: payload["issued_token_type"],
          refresh_token: payload["refresh_token"],
          id_token: payload["id_token"],
          raw: payload
        )
      end
    end
  end
end
