# frozen_string_literal: true

require "json"
require "jwt"
require "uri"

module Keycardai
  module OAuth
    # Resolves and caches JWKS verification keys for an issuer (RFC 7517), so
    # bearer-token verification on a hot path does not hit the network per
    # request. Resolution is a lookup keyed by (issuer, kid): discover the
    # issuer's jwks_uri (RFC 8414), fetch the key set, select the key matching
    # the kid. Both steps are cached with a TTL; the key cache is bounded and
    # evicts its oldest entry on overflow.
    #
    # The cache is in-memory and local to this instance. Thread-safe:
    # concurrent resolutions for the same issuer are de-duplicated so a burst
    # of cold-cache requests triggers a single discovery and a single JWKS
    # fetch.
    class JWKSKeyring
      DEFAULT_KEY_TTL = 300
      DEFAULT_DISCOVERY_TTL = 3600
      DEFAULT_FETCH_TIMEOUT = 10
      MAX_CACHED_KEYS = 256

      # @param http_client [#get] pluggable transport (see HTTP::NetHTTPClient)
      # @param key_ttl [Numeric] per-key cache lifetime in seconds
      # @param discovery_ttl [Numeric] jwks_uri cache lifetime in seconds
      # @param fetch_timeout [Numeric] timeout for discovery and JWKS fetches
      # @param clock [#call] returns the current Time; override in tests
      def initialize(http_client: HTTP::NetHTTPClient.new, key_ttl: DEFAULT_KEY_TTL,
                     discovery_ttl: DEFAULT_DISCOVERY_TTL, fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                     clock: -> { Time.now })
        @http_client = http_client
        @key_ttl = key_ttl
        @discovery_ttl = discovery_ttl
        @fetch_timeout = fetch_timeout
        @clock = clock
        @keys = {}
        @discovery = {}
        @issuer_locks = {}
        @mutex = Mutex.new
      end

      # Resolve the verification key for a token's issuer and kid.
      #
      # @param issuer [String] the token issuer URL
      # @param kid [String] the kid from the JWT header
      # @return [OpenSSL::PKey::PKey] the verification key
      # @raise [JWKSDiscoveryError] discovery failed or metadata has no jwks_uri
      # @raise [JWKSUriValidationError] jwks_uri is cross-origin with the issuer
      # @raise [JWKSFetchError] the JWKS endpoint failed
      # @raise [JWKSKeyNotFoundError] the kid is absent from the fetched JWKS
      def key(issuer, kid)
        cached = @mutex.synchronize { fresh_key(issuer, kid) }
        return cached if cached

        issuer_lock(issuer).synchronize do
          cached = @mutex.synchronize { fresh_key(issuer, kid) }
          cached || resolve(issuer, kid)
        end
      end

      # Drop cached keys and discovery results, for one issuer or all.
      #
      # @param issuer [String, nil] limit invalidation to this issuer
      # @return [void]
      def invalidate(issuer = nil)
        @mutex.synchronize do
          if issuer
            @keys.delete_if { |(cached_issuer, _), _| cached_issuer == issuer }
            @discovery.delete(issuer)
          else
            @keys.clear
            @discovery.clear
          end
        end
      end

      private

      def fresh_key(issuer, kid)
        entry = @keys[[issuer, kid]]
        return nil unless entry
        return nil if now - entry[:cached_at] > @key_ttl

        entry[:key]
      end

      def issuer_lock(issuer)
        @mutex.synchronize { @issuer_locks[issuer] ||= Mutex.new }
      end

      def resolve(issuer, kid)
        jwks_uri = resolve_jwks_uri(issuer)
        jwk = fetch_jwks(jwks_uri).find { |candidate| candidate["kid"] == kid }
        raise JWKSKeyNotFoundError, "kid #{kid.inspect} not found in JWKS for #{issuer}" unless jwk

        key = import_key(jwk)
        cache_key(issuer, kid, key)
        key
      end

      def resolve_jwks_uri(issuer)
        cached = @mutex.synchronize do
          entry = @discovery[issuer]
          entry[:jwks_uri] if entry && now - entry[:fetched_at] <= @discovery_ttl
        end
        return cached if cached

        jwks_uri = discover_jwks_uri(issuer)
        assert_same_origin(issuer, jwks_uri)
        @mutex.synchronize { @discovery[issuer] = { jwks_uri: jwks_uri, fetched_at: now } }
        jwks_uri
      end

      def discover_jwks_uri(issuer)
        metadata = OAuth.fetch_authorization_server_metadata(issuer, http_client: @http_client,
                                                                     timeout: @fetch_timeout)
        metadata.jwks_uri || raise(JWKSDiscoveryError, "metadata for #{issuer} has no jwks_uri")
      rescue HTTPError, ProtocolError, NetworkError, ConfigurationError => e
        raise JWKSDiscoveryError, "discovery for #{issuer} failed: #{e.message}"
      end

      def assert_same_origin(issuer, jwks_uri)
        issuer_uri = URI(issuer)
        keys_uri = URI(jwks_uri)
        same = issuer_uri.scheme == keys_uri.scheme && issuer_uri.host == keys_uri.host &&
               issuer_uri.port == keys_uri.port
        return if same

        raise JWKSUriValidationError, "jwks_uri #{jwks_uri} is cross-origin with issuer #{issuer}"
      end

      def fetch_jwks(jwks_uri)
        response = begin
          @http_client.get(jwks_uri, headers: { "Accept" => "application/json" }, timeout: @fetch_timeout)
        rescue NetworkError => e
          raise JWKSFetchError, "JWKS fetch from #{jwks_uri} failed: #{e.message}"
        end
        raise JWKSFetchError, "JWKS fetch from #{jwks_uri} returned HTTP #{response.status}" unless response.success?

        document = begin
          JSON.parse(response.body)
        rescue JSON::ParserError
          raise JWKSFetchError, "JWKS from #{jwks_uri} is invalid JSON"
        end
        document["keys"] || raise(JWKSFetchError, "JWKS from #{jwks_uri} has no keys field")
      end

      def import_key(jwk)
        JWT::JWK.import(jwk.transform_keys(&:to_sym)).verify_key
      rescue JWT::JWKError, ArgumentError
        raise JWKSKeyNotFoundError, "JWK with kid #{jwk["kid"].inspect} could not be converted to a verification key"
      end

      def cache_key(issuer, kid, key)
        @mutex.synchronize do
          @keys.shift while @keys.size >= MAX_CACHED_KEYS
          @keys[[issuer, kid]] = { key: key, cached_at: now }
        end
      end

      def now
        @clock.call
      end
    end
  end
end
