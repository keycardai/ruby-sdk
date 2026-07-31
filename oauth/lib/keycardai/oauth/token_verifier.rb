# frozen_string_literal: true

module Keycardai
  module OAuth
    # A verified bearer token: the raw compact JWT plus its verified claims,
    # with convenience accessors for the RFC 9068 profile.
    AccessToken = Data.define(:token, :claims) do
      # @return [String] the token's subject
      def subject
        claims["sub"]
      end

      # @return [String]
      def client_id
        claims["client_id"]
      end

      # @return [String] the issuer that minted the token
      def issuer
        claims["iss"]
      end

      # @return [Array<String>] audiences the token was minted for
      def audiences
        Array(claims["aud"])
      end

      # @return [Array<String>] scopes granted to the token
      def scopes
        claims["scope"].to_s.split
      end

      # @return [Time]
      def expires_at
        Time.at(claims["exp"])
      end
    end

    # Server-tier bearer-token verification: JWTVerifier over a JWKSKeyring,
    # returning an AccessToken. Construct once per server with the trusted
    # zone issuer(s); JWKS and discovery caches are keyed by issuer so no
    # zone's keys are ever served for another.
    class TokenVerifier
      # @param issuers [String, Array<String>] trusted zone issuer URL(s)
      # @param audiences [String, Array<String>, nil] when set, tokens must
      #   carry an intersecting aud
      # @param http_client [#get] pluggable transport
      # @param key_ttl [Numeric] JWKS key cache lifetime in seconds
      # @param discovery_ttl [Numeric] jwks_uri cache lifetime in seconds
      # @param fetch_timeout [Numeric] discovery and JWKS fetch timeout
      # @param clock [#call] returns the current Time; override in tests
      # @raise [ConfigurationError] no trusted issuer
      def initialize(issuers:, audiences: nil, http_client: HTTP::NetHTTPClient.new,
                     key_ttl: JWKSKeyring::DEFAULT_KEY_TTL, discovery_ttl: JWKSKeyring::DEFAULT_DISCOVERY_TTL,
                     fetch_timeout: JWKSKeyring::DEFAULT_FETCH_TIMEOUT, clock: -> { Time.now })
        @issuers = Array(issuers).reject { |issuer| issuer.nil? || issuer.empty? }
        raise ConfigurationError, "TokenVerifier requires at least one trusted issuer" if @issuers.empty?

        @audiences = audiences
        @clock = clock
        @keyring = JWKSKeyring.new(http_client: http_client, key_ttl: key_ttl,
                                   discovery_ttl: discovery_ttl, fetch_timeout: fetch_timeout, clock: clock)
      end

      # Verify a bearer token against the configured issuer allowlist.
      #
      # @param token [String]
      # @return [AccessToken]
      # @raise [InvalidTokenError, JWKSError]
      def verify_token(token)
        verify_against(@issuers, token)
      end

      # Verify a bearer token pinned to one zone's issuer. A token minted by
      # any other zone is rejected before key resolution, and an issuer
      # outside the configured allowlist fails closed.
      #
      # @param token [String]
      # @param issuer [String] the zone's issuer URL
      # @return [AccessToken]
      # @raise [InvalidTokenError, JWKSError]
      def verify_token_for_zone(token, issuer)
        raise InvalidTokenError, "zone issuer is not configured on this verifier" unless @issuers.include?(issuer)

        verify_against([issuer], token)
      end

      # Drop all cached keys and discovery results.
      #
      # @return [void]
      def clear_cache
        @keyring.invalidate
      end

      private

      def verify_against(issuers, token)
        claims = JWTVerifier.new(issuers: issuers, keyring: @keyring, audiences: @audiences,
                                 clock: @clock).verify(token)
        AccessToken.new(token: token, claims: claims)
      end
    end
  end
end
