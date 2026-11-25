# frozen_string_literal: true

require "uri"

module Keycardai
  # Token revocation (RFC 7009).
  module OAuth
    # Revoke a token (RFC 7009). A Keycard refresh token revokes its session.
    # HTTP 200 succeeds without a response body, including for unknown,
    # expired, invalid, or already revoked tokens.
    #
    # @param issuer [String, nil] the zone issuer URL; HTTPS is required for discovery
    # @param metadata [AuthorizationServerMetadata, nil] pre-discovered metadata
    # @param token [String] the token to revoke
    # @param token_type_hint [String] the hint sent to the revocation endpoint
    # @param client_id [String, nil] required unless credential is set
    # @param client_secret [String, nil] use HTTP Basic with client_id
    # @param credential [#client_authentication, nil] authenticates in place of client_id and client_secret
    # @param http_client [#get, #post_form] pluggable transport
    # @param timeout [Numeric, nil] request timeout in seconds
    # @return [nil]
    # @raise [ConfigurationError] invalid inputs or missing or invalid revocation endpoint
    # @raise [OAuthError, HTTPError, ProtocolError, NetworkError]
    def self.revoke_token(issuer = nil, token: nil, metadata: nil, client_id: nil, client_secret: nil,
                          credential: nil, token_type_hint: "refresh_token", http_client: HTTP::NetHTTPClient.new,
                          timeout: nil)
      raise ConfigurationError, "token must be a non-empty string" unless token.is_a?(String) && !token.empty?

      ClientAuth.validate(credential: credential, client_id: client_id, client_secret: client_secret)
      metadata, issuer = resolve_revocation_metadata(issuer, metadata, http_client: http_client, timeout: timeout)
      endpoint = require_revocation_https(metadata.revocation_endpoint, "revocation_endpoint")
      params = [["token", token], ["token_type_hint", token_type_hint]]
      params, headers = ClientAuth.apply(params, { "Accept" => "application/json" },
                                         issuer: issuer, endpoint: issuer, credential: credential,
                                         client_id: client_id, client_secret: client_secret)
      response = http_client.post_form(endpoint, params, headers: headers, timeout: timeout)
      raise TokenRequests.error_for(response, endpoint_name: "revocation endpoint") unless response.status == 200
    end

    def self.revocation_issuer(issuer, metadata)
      zone = issuer || metadata&.issuer
      raise ConfigurationError, "provide an issuer or metadata" unless zone.is_a?(String) && !zone.empty?
      return zone unless metadata
      return zone if same_revocation_issuer?(zone, metadata.issuer)

      raise ConfigurationError, "issuer does not match the metadata issuer"
    end
    private_class_method :revocation_issuer

    def self.same_revocation_issuer?(zone, discovered)
      discovered.is_a?(String) && zone.chomp("/") == discovered.chomp("/")
    end
    private_class_method :same_revocation_issuer?

    def self.resolve_revocation_metadata(issuer, metadata, http_client:, timeout:)
      issuer = revocation_issuer(issuer, metadata)
      return [metadata, issuer] if metadata

      require_revocation_https(issuer, "issuer")
      discovered = fetch_authorization_server_metadata(issuer, http_client: http_client, timeout: timeout)
      [discovered, discovered.issuer]
    end
    private_class_method :resolve_revocation_metadata

    def self.require_revocation_https(url, field)
      uri = URI.parse(url) if url.is_a?(String)
      return url if uri.is_a?(URI::HTTPS) && !uri.host.to_s.empty?

      raise ConfigurationError, "#{field} must be an HTTPS URL"
    rescue URI::InvalidURIError
      raise ConfigurationError, "#{field} must be an HTTPS URL"
    end
    private_class_method :require_revocation_https
  end
end
