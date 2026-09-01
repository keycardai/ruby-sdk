# frozen_string_literal: true

require "json"

module Keycardai
  # The OpenID Connect UserInfo call (OIDC Core 1.0 §5.3): the operation, its
  # response type, and the response-parsing internals.
  module OAuth
    # The signed-in user's identity claims (OIDC Core 1.0 §5.3). +sub+ is the
    # only claim OIDC requires and is validated present; the claims document is
    # returned exactly as the issuer sent it, nothing filtered to a known set,
    # and reachable through +[]+.
    UserInfoResponse = Data.define(:sub, :claims) do
      # @param claim [String] a claim name
      # @return [Object, nil] the claim's value from the full document
      def [](claim)
        claims[claim]
      end
    end

    # Fetch the signed-in user's identity claims from the issuer's UserInfo
    # endpoint (OIDC Core 1.0 §5.3).
    #
    # Keycard zone access tokens are authorization-only, so claims such as
    # +email+ or +groups+ live behind the issuer's +userinfo_endpoint+ rather
    # than in the token. The endpoint comes from discovery unless +metadata+ is
    # supplied, in which case the caller owns caching and refreshing it.
    #
    # The access token is presented as a Bearer credential and the request
    # carries no client authentication: UserInfo authenticates the user, not
    # the client. Signed (+application/jwt+) responses are not supported.
    # Nothing is cached; claims can change server-side, so caching per token is
    # the caller's concern.
    #
    # @param issuer [String] the zone's issuer URL
    # @param access_token [String] the user's access token
    # @param metadata [AuthorizationServerMetadata, nil] pre-discovered
    #   metadata; when given, no discovery request is made
    # @param http_client [#get] pluggable transport
    # @param timeout [Numeric, nil]
    # @return [UserInfoResponse]
    # @raise [ConfigurationError] the metadata advertises no userinfo_endpoint,
    #   raised before any request
    # @raise [OAuthError] the endpoint rejected the token (HTTP 401), carrying
    #   the error code from the WWW-Authenticate challenge
    # @raise [HTTPError] any other non-2xx response
    # @raise [ProtocolError] a signed or non-JSON body, or claims without sub
    # @raise [NetworkError] transport failure
    def self.fetch_userinfo(issuer, access_token:, metadata: nil,
                            http_client: HTTP::NetHTTPClient.new, timeout: nil)
      metadata ||= fetch_authorization_server_metadata(issuer, http_client: http_client, timeout: timeout)
      endpoint = metadata.userinfo_endpoint
      if endpoint.nil? || endpoint.empty?
        raise ConfigurationError,
              "authorization server #{metadata.issuer} advertises no userinfo_endpoint"
      end

      headers = { "Accept" => "application/json", "Authorization" => "Bearer #{access_token}" }
      UserInfo.parse_response(http_client.get(endpoint, headers: headers, timeout: timeout))
    end

    # Internals of the UserInfo call. Not public API.
    module UserInfo
      module_function

      # @param response [HTTP::Response]
      # @return [UserInfoResponse]
      def parse_response(response)
        raise error_for(response) unless response.success?

        content_type = header(response, "content-type").to_s
        if content_type.downcase.include?("application/jwt")
          raise ProtocolError.new("userinfo response content type #{content_type} is not supported",
                                  code: "invalid_response")
        end

        claims = parse_claims(response.body)
        sub = claims["sub"]
        unless sub.is_a?(String) && !sub.empty?
          raise ProtocolError.new("userinfo response has no sub claim", code: "invalid_response")
        end

        UserInfoResponse.new(sub: sub, claims: claims)
      end

      def parse_claims(body)
        claims = JSON.parse(body)
        unless claims.is_a?(Hash)
          raise ProtocolError.new("userinfo response is not a JSON object", code: "invalid_response")
        end

        claims
      rescue JSON::ParserError
        raise ProtocolError.new("userinfo response is not valid JSON", code: "invalid_response")
      end

      # RFC 6750 §3: a 401 carries the reason in the WWW-Authenticate
      # challenge. Anything else non-2xx is a plain HTTP error.
      #
      # @param response [HTTP::Response]
      # @return [OAuthError, HTTPError]
      def error_for(response)
        return http_error(response) unless response.status == 401

        error = challenge_error(header(response, "www-authenticate"))
        OAuthError.new("userinfo request was rejected with #{error}",
                       error: error, status: response.status, body: response.body)
      end

      def http_error(response)
        HTTPError.new("userinfo endpoint returned HTTP #{response.status}",
                      status: response.status, body: response.body)
      end

      # The challenge's error code, defaulting to invalid_token when the
      # challenge is absent or carries no error parameter.
      def challenge_error(www_authenticate)
        www_authenticate.to_s[/error\s*=\s*"?([^",\s]+)"?/, 1] || "invalid_token"
      end

      # Header names are case-insensitive (RFC 9110 §5.1) and Net::HTTP hands
      # back array values.
      def header(response, name)
        _, value = response.headers.find { |key, _| key.to_s.downcase == name }
        value.is_a?(Array) ? value.first : value
      end
    end
  end
end
