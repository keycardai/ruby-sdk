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
      REFRESH_TOKEN = "refresh_token"
      TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
      DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    end

    # A token issued by the authorization server, the shared response shape of
    # token exchange, client credentials, and the authorization-code exchange.
    # +scope+ is parsed from the space-separated wire value into an array;
    # +token_type+ defaults to "Bearer" when the server omits it. The complete
    # response body is preserved in +raw+.
    TokenResponse = Data.define(
      :access_token, :token_type, :expires_in, :scope, :issued_token_type, :refresh_token, :id_token, :raw
    ) do
      include PrintedForm

      # Shows every member except the access, refresh, and ID tokens, and
      # only the field names of +raw+. #to_h and +raw+ keep the tokens, so a
      # stored response can be used.
      #
      # @return [String]
      def inspect
        shown = to_h.except(:access_token, :refresh_token, :id_token, :raw)
                    .map { |name, value| "#{name}=#{value.inspect}" }
        "#<data #{self.class} #{shown.join(", ")}, raw=#{raw.to_h.keys.inspect}>"
      end

      # @param payload [Hash] the parsed token-endpoint response body
      # @return [TokenResponse]
      # @raise [ProtocolError] invalid_response when the response has no
      #   access token, or a scope that is not a string
      def self.from_wire(payload)
        validate(payload)
        new(
          access_token: payload["access_token"],
          token_type: payload["token_type"] || "Bearer",
          expires_in: payload["expires_in"],
          scope: payload["scope"]&.split,
          issued_token_type: payload["issued_token_type"],
          refresh_token: payload["refresh_token"],
          id_token: payload["id_token"],
          raw: payload
        )
      end

      def self.validate(payload)
        access_token = payload["access_token"]
        unless access_token.is_a?(String) && !access_token.empty?
          raise ProtocolError.new("token response has no access_token", code: "invalid_response")
        end
        return if payload["scope"].nil? || payload["scope"].is_a?(String)

        raise ProtocolError.new("token response scope is not a string", code: "invalid_response")
      end
      private_class_method :validate
    end
  end
end
