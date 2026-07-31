# frozen_string_literal: true

require "uri"

module Keycardai
  # Authorization-code grant building blocks (RFC 6749 §4.1 + RFC 7636): the
  # authorize-URL builder and the back-channel code exchange.
  module OAuth
    # Build the authorization request URL.
    #
    # @param authorization_endpoint [String] from discovery
    # @param client_id [String]
    # @param redirect_uri [String]
    # @param code_challenge [String] the PKCE challenge
    # @param code_challenge_method [String] the method the challenge was derived with
    # @param scope [String, nil] space-separated scopes
    # @param state [String, nil] CSRF state value
    # @param resource [String, nil] RFC 8707 resource indicator
    # @return [String] the authorize URL
    def self.build_authorize_url(authorization_endpoint, client_id:, redirect_uri:, code_challenge:,
                                 code_challenge_method: "S256", scope: nil, state: nil, resource: nil)
      params = {
        "response_type" => "code",
        "client_id" => client_id,
        "redirect_uri" => redirect_uri,
        "code_challenge" => code_challenge,
        "code_challenge_method" => code_challenge_method,
        "scope" => scope,
        "state" => state,
        "resource" => resource
      }.compact

      uri = URI(authorization_endpoint)
      query = URI.encode_www_form(params)
      uri.query = uri.query.nil? || uri.query.empty? ? query : "#{uri.query}&#{query}"
      uri.to_s
    end

    # Exchange an authorization code for a token (RFC 6749 §4.1.3). A public
    # client sends its client_id in the body; a confidential client
    # authenticates with HTTP Basic and omits client_id from the body.
    #
    # @param issuer [String] the zone's issuer URL; supplies the token endpoint
    # @param code [String] the authorization code from the redirect
    # @param code_verifier [String] the PKCE verifier matching the challenge
    # @param redirect_uri [String] must match the authorization request
    # @param client_id [String, nil] public-client identifier
    # @param client_secret [String, nil] confidential-client secret; requires client_id
    # @param resource [String, nil] RFC 8707 resource indicator
    # @param http_client [#get, #post_form] pluggable transport
    # @param timeout [Numeric, nil]
    # @return [TokenResponse]
    # @raise [OAuthError] an RFC 6749 §5.2 error response (invalid_grant, ...)
    # @raise [HTTPError, ProtocolError, NetworkError, ConfigurationError]
    def self.exchange_authorization_code(issuer, code:, code_verifier:, redirect_uri:, client_id: nil,
                                         client_secret: nil, resource: nil,
                                         http_client: HTTP::NetHTTPClient.new, timeout: nil)
      raise ConfigurationError, "client_secret requires client_id" if client_secret && client_id.nil?

      metadata = fetch_authorization_server_metadata(issuer, http_client: http_client, timeout: timeout)
      endpoint = metadata.token_endpoint ||
                 raise(ProtocolError.new("metadata for #{issuer} has no token_endpoint", code: "invalid_metadata"))

      # A confidential client authenticates with Basic and omits client_id
      # from the body; a public client carries client_id in the body.
      params = {
        "grant_type" => GrantType::AUTHORIZATION_CODE,
        "code" => code,
        "code_verifier" => code_verifier,
        "redirect_uri" => redirect_uri,
        "client_id" => client_secret ? nil : client_id,
        "resource" => resource
      }.compact
      headers = { "Accept" => "application/json" }
      headers["Authorization"] = HTTP.basic_authorization(client_id, client_secret) if client_secret

      TokenRequests.parse_response(http_client.post_form(endpoint, params, headers: headers, timeout: timeout))
    end
  end
end
