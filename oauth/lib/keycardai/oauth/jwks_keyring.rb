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
      # Shortest interval between two JWKS fetches for one jwks_uri caused by a
      # kid the cached key set does not hold. The checks before the key lookup
      # read the unsigned token, so a forged token can name any kid.
      DEFAULT_REFETCH_COOLDOWN = 30
      MAX_CACHED_KEYS = 256

      # @param http_client [#get] pluggable transport (see HTTP::NetHTTPClient)
      # @param key_ttl [Numeric] per-key cache lifetime in seconds
      # @param discovery_ttl [Numeric] jwks_uri cache lifetime in seconds
      # @param fetch_timeout [Numeric] timeout for discovery and JWKS fetches
      # @param refetch_cooldown [Numeric] seconds before a kid missing from the
      #   cached key set triggers another fetch; 0 fetches on every miss
      # @param clock [#call] returns the current Time; override in tests
      def initialize(http_client: HTTP::NetHTTPClient.new, key_ttl: DEFAULT_KEY_TTL,
                     discovery_ttl: DEFAULT_DISCOVERY_TTL, fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                     refetch_cooldown: DEFAULT_REFETCH_COOLDOWN, clock: -> { Time.now })
        @http_client = http_client
        @key_ttl = key_ttl
        @discovery_ttl = discovery_ttl
        @fetch_timeout = fetch_timeout
        @refetch_cooldown = refetch_cooldown
        @clock = clock
        @keys = {}
        @discovery = {}
        @key_sets = {} # jwks_uri => { keys:, fetched_at: }
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
            entry = @discovery.delete(issuer)
            @key_sets.delete(entry[:jwks_uri]) if entry
          else
            @keys.clear
            @discovery.clear
            @key_sets.clear
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
        jwk = key_from_set(issuer, kid, jwks_uri)

        key = import_key(jwk)
        cache_key(issuer, kid, key)
        key
      end

      # The cached key set first: a kid it holds imports with no fetch, and a kid
      # it lacks refetches at most once per cooldown, so a rotated-in key is found
      # once the cooldown has passed.
      def key_from_set(issuer, kid, jwks_uri)
        cached = fresh_key_set(jwks_uri)
        if cached
          jwk = cached[:keys].find { |candidate| candidate["kid"] == kid }
          return jwk if jwk

          raise_not_found(issuer, kid) if now - cached[:fetched_at] < @refetch_cooldown
        end

        keys = fetch_jwks(jwks_uri)
        @mutex.synchronize { @key_sets[jwks_uri] = { keys: keys, fetched_at: now } }
        keys.find { |candidate| candidate["kid"] == kid } || raise_not_found(issuer, kid)
      end

      def fresh_key_set(jwks_uri)
        @mutex.synchronize do
          entry = @key_sets[jwks_uri]
          entry if entry && now - entry[:fetched_at] <= @key_ttl
        end
      end

      def raise_not_found(issuer, kid)
        raise JWKSKeyNotFoundError, "kid #{kid.inspect} not found in JWKS for #{issuer}"
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
