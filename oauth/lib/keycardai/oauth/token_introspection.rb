# frozen_string_literal: true

require "json"
require "uri"

module Keycardai
  # Token introspection (RFC 7662).
  module OAuth
    # An RFC 7662 result. Optional claims are nil when absent. +scope+ is a
    # list of scopes, and +iat+ and +exp+ are Unix seconds. +raw+ preserves
    # the wire claims, including claims without dedicated readers.
    TokenIntrospection = Data.define(:active, :token_type, :iss, :sub, :client_id, :aud,
                                     :scope, :sid, :jti, :iat, :exp, :raw) do
      def initialize(active:, token_type: nil, iss: nil, sub: nil, client_id: nil, aud: nil,
                     scope: nil, sid: nil, jti: nil, iat: nil, exp: nil, raw: {})
        super
      end

      # @param claim [String] a claim name
      # @return [Object, nil] the claim's wire value
      def [](claim)
        raw[claim]
      end
    end

    # Check a token's current status with its authorization server (RFC 7662).
    # An inactive token is a successful result. Results are not cached.
    #
    # @param issuer [String, nil] the HTTPS zone issuer URL
    # @param token [String] an access token or refresh token
    # @param credential [#client_authentication] confidential client credential
    # @param metadata [AuthorizationServerMetadata, nil] pre-discovered metadata
    # @param token_type_hint [String, nil] optional hint sent as provided
    # @param http_client [#get, #post_form] pluggable transport
    # @param timeout [Numeric, nil] request timeout in seconds
    # @return [TokenIntrospection]
    # @raise [ConfigurationError] invalid inputs or missing or invalid introspection endpoint
    # @raise [OAuthError, HTTPError, ProtocolError, NetworkError]
    def self.introspect_token(issuer = nil, token: nil, credential: nil, metadata: nil, token_type_hint: nil,
                              http_client: HTTP::NetHTTPClient.new, timeout: nil)
      raise ConfigurationError, "token must be a non-empty string" unless token.is_a?(String) && !token.empty?

      ClientAuth.validate(credential: credential, client_id: nil)
      metadata, issuer = Introspection.resolve_metadata(issuer, metadata, http_client: http_client, timeout: timeout)
      params = [["token", token]]
      params << ["token_type_hint", token_type_hint] unless token_type_hint.nil?
      Introspection.post(metadata, params, issuer: issuer, credential: credential, http_client: http_client,
                                           timeout: timeout)
    end

    # Internal request and response handling for token introspection.
    module Introspection
      module_function

      def resolve_metadata(issuer, metadata, http_client:, timeout:)
        if metadata
          zone = require_https_url(metadata.issuer, "metadata issuer")
          matches = issuer.is_a?(String) && issuer.chomp("/") == zone.chomp("/")
          return [metadata, issuer || zone] if issuer.nil? || matches

          raise ConfigurationError, "issuer does not match the metadata issuer"
        end

        discovered = OAuth.fetch_authorization_server_metadata(require_https_url(issuer, "issuer"),
                                                               http_client: http_client, timeout: timeout)
        [discovered, discovered.issuer]
      end

      def require_https_url(url, field)
        uri = URI.parse(url) if url.is_a?(String)
        return url if uri.is_a?(URI::HTTPS) && !uri.host.to_s.empty?

        raise ConfigurationError, "#{field} must be an HTTPS URL"
      rescue URI::InvalidURIError
        raise ConfigurationError, "#{field} must be an HTTPS URL"
      end

      def post(metadata, params, issuer:, credential:, http_client:, timeout:)
        endpoint = require_https_url(metadata.introspection_endpoint, "introspection_endpoint")
        params, headers = ClientAuth.apply(params, { "Accept" => "application/json" },
                                           issuer: issuer, endpoint: metadata.issuer, credential: credential)
        parse_response(http_client.post_form(endpoint, params, headers: headers, timeout: timeout))
      end

      def parse_response(response)
        raise TokenRequests.error_for(response, endpoint_name: "introspection endpoint") unless response.status == 200

        document = JSON.parse(response.body)
        raise invalid_response("introspection response is not a JSON object") unless document.is_a?(Hash)

        case document["active"]
        when true then active_result(document)
        when false then TokenIntrospection.new(active: false, raw: { "active" => false })
        else raise invalid_response("introspection response must contain a boolean active field")
        end
      rescue JSON::ParserError
        raise invalid_response("introspection response is not valid JSON")
      end

      def active_result(document)
        scope = document["scope"]
        raise invalid_response("introspection response scope is not a string") unless scope.nil? || scope.is_a?(String)

        fields = (TokenIntrospection.members - [:raw]).to_h { |name| [name, document[name.to_s]] }
        TokenIntrospection.new(**fields, scope: scope&.split, raw: document)
      end

      def invalid_response(message)
        ProtocolError.new(message, code: "invalid_response", status: 200)
      end
    end
    private_constant :Introspection
  end
end
