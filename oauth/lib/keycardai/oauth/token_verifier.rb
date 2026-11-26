# frozen_string_literal: true

module Keycardai
  module OAuth
    # A verified bearer token: the raw compact JWT plus its verified claims,
    # with convenience accessors for the RFC 9068 profile.
    #
    # Four accessors answer distinct questions about the caller, and picking
    # the wrong one is a real bug rather than a style choice:
    #
    # - #client_id is the OAuth client that authenticated, so it names the
    #   credential. It rotates, so it does not stably identify an application.
    # - #keycard_app_id is the stable Keycard application identifier. Key on
    #   this to answer "which application is calling", whatever the grant type
    #   or credential. For user agents it equals #client_id.
    # - #subject is the user identifier on a user-present token and the
    #   application identifier on an application token.
    # - #subject_profile distinguishes those two cases directly, rather than
    #   leaving a consumer to infer it from #subject against #client_id.
    #
    # #subject and #client_id are RFC 9068. The other two are Keycard claims
    # and are absent from a non-Keycard token, so they return nil there.
    AccessToken = Data.define(:token, :claims) do
      include PrintedForm::Serializable

      # Shows the claims and leaves out the bearer token. #token keeps it.
      #
      # @return [String]
      def inspect
        "#<data #{self.class} claims=#{claims.inspect}>"
      end

      # @return [String] the token's subject: the user for a user-present
      #   token, the application for an application token
      def subject
        claims["sub"]
      end

      # Whether a user authorized this access or an application is acting on
      # its own behalf. Reads the Keycard `sub_profile` claim.
      #
      # @return ["user", "app", nil] nil on a non-Keycard token
      def subject_profile
        claims["sub_profile"]
      end

      # The stable Keycard application identifier, which is the claim to key
      # on when identifying the calling application.
      #
      # @return [String, nil] nil on a non-Keycard token
      def keycard_app_id
        claims["keycard_app_id"]
      end

      # @return [String] the OAuth client that authenticated, meaning the
      #   credential rather than the application
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
      # @return [ResourceBinding] the validated resource-binding mode
      attr_reader :resource_binding
      # @return [Array<String>] trusted zone issuer URLs
      attr_reader :issuers
      # @return [Hash{String => String}] zone ID to issuer URL map in zone modes
      attr_reader :zone_issuers

      # @param issuers [String, Array<String>, Hash{String => String}, nil] trusted zone issuer URL(s)
      # @param issuer [String, nil] single issuer URL, or base issuer URL for zone-scoped modes
      # @param audiences [String, Array<String>, nil] accepted audiences in multi_resource or legacy mode
      # @param resource_identifier [String, nil] exact HTTP(S) URL or URN in single-resource mode
      # @param resource_identifiers_by_zone [Hash{String => String}, nil] zone ID to identifier map
      # @param multi_resource [Boolean] explicit multi-resource or shared-discovery opt-in
      # @param allow_any_audience [Boolean] explicit opt-out from audience validation
      # @param resource_binding [ResourceBinding, nil] pre-validated binding (internal composition)
      # @param http_client [#get] pluggable transport
      # @param key_ttl [Numeric] JWKS key cache lifetime in seconds
      # @param discovery_ttl [Numeric] jwks_uri cache lifetime in seconds
      # @param fetch_timeout [Numeric] discovery and JWKS fetch timeout
      # @param clock [#call] returns the current Time; override in tests
      # @raise [ConfigurationError] invalid or conflicting mode options or no trusted issuer
      def initialize(issuers: nil, issuer: nil, audiences: nil,
                     resource_identifier: nil, resource_identifiers_by_zone: nil,
                     multi_resource: false, allow_any_audience: false,
                     resource_binding: nil,
                     http_client: HTTP::NetHTTPClient.new,
                     key_ttl: JWKSKeyring::DEFAULT_KEY_TTL, discovery_ttl: JWKSKeyring::DEFAULT_DISCOVERY_TTL,
                     fetch_timeout: JWKSKeyring::DEFAULT_FETCH_TIMEOUT, clock: MetadataRetry::WALL_CLOCK)
        @resource_binding = resource_binding || ResourceBinding.resolve(
          resource_identifier: resource_identifier,
          resource_identifiers_by_zone: resource_identifiers_by_zone,
          multi_resource: multi_resource,
          allow_any_audience: allow_any_audience,
          audiences: audiences,
          component: "Keycardai::OAuth::TokenVerifier"
        )
        @issuers, @zone_issuers = resolve_issuers(issuers, issuer)
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
        raise InvalidTokenError, "per-zone verifier requires verify_token_for_zone" if @resource_binding.per_zone?

        verify_against(@issuers, token, @resource_binding.audiences)
      end

      # Verify a bearer token pinned to one zone's issuer or zone ID. A token
      # minted by any other zone is rejected before key resolution, and an
      # unconfigured zone fails closed.
      #
      # @param token [String]
      # @param zone_or_issuer [String] zone ID (in zone modes) or zone issuer URL
      # @return [AccessToken]
      # @raise [InvalidTokenError, JWKSError]
      def verify_token_for_zone(token, zone_or_issuer)
        return verify_per_zone(token, zone_or_issuer) if @resource_binding.per_zone?
        return verify_shared_zone(token, zone_or_issuer) if @resource_binding.shared_discovery?
        unless @issuers.include?(zone_or_issuer)
          raise InvalidTokenError, "zone issuer is not configured on this verifier"
        end

        verify_against([zone_or_issuer], token, @resource_binding.audiences)
      end

      # Drop all cached keys and discovery results.
      #
      # @return [void]
      def clear_cache
        @keyring.invalidate
      end

      private

      def verify_per_zone(token, zone_or_issuer)
        zone_id = @zone_issuers.key?(zone_or_issuer) ? zone_or_issuer : @zone_issuers.key(zone_or_issuer)
        raise InvalidTokenError, "zone is not configured on this verifier" unless zone_id

        verify_against([@zone_issuers[zone_id]], token, [@resource_binding.zone_identifiers[zone_id].raw])
      end

      def verify_shared_zone(token, zone_or_issuer)
        zone_issuer = @zone_issuers[zone_or_issuer] || (@issuers.include?(zone_or_issuer) ? zone_or_issuer : nil)
        raise InvalidTokenError, "zone issuer is not configured on this verifier" unless zone_issuer

        verify_against([zone_issuer], token, @resource_binding.audiences)
      end

      def resolve_issuers(issuers, issuer)
        return resolve_zone_issuers(issuers, issuer) if @resource_binding.zone_mode?

        raw = issuers.nil? ? issuer : issuers
        list = Array(raw).reject { |item| item.nil? || item.empty? }.freeze
        raise ConfigurationError, "TokenVerifier requires at least one trusted issuer" if list.empty?

        [list, {}.freeze]
      end

      def resolve_zone_issuers(issuers, issuer)
        return resolve_zone_issuer_hash(issuers) if issuers.is_a?(Hash)

        base = issuer || (issuers if issuers.is_a?(String))
        return resolve_derived_zone_issuers(base, issuers) unless base.to_s.empty?
        return match_zone_issuer_array(issuers) if issuers.is_a?(Array) && !issuers.empty?

        raise ConfigurationError, "TokenVerifier requires at least one trusted issuer"
      end

      def resolve_zone_issuer_hash(issuers)
        expected = @resource_binding.zone_identifiers.keys.sort
        unless issuers.keys.sort == expected
          raise ConfigurationError, "issuers keys must match resource_identifiers_by_zone keys"
        end

        zone_map = issuers.transform_values(&:to_s).freeze
        [zone_map.values.freeze, zone_map]
      end

      def resolve_derived_zone_issuers(base, issuers)
        zone_map = @resource_binding.zone_issuers(base).freeze
        if issuers.is_a?(Array) && issuers.map { |i| i.to_s.chomp("/") }.sort != zone_map.values.sort
          raise ConfigurationError, "trusted issuers must match the zones in resource_identifiers_by_zone"
        end

        [zone_map.values.freeze, zone_map]
      end

      # Trusted issuers keep their configured spelling, so a token whose iss
      # carries a trailing slash still matches it exactly.
      def match_zone_issuer_array(issuers)
        configured = issuers.map(&:to_s)
        zone_map = @resource_binding.zone_identifiers.keys.to_h do |zone_id|
          [zone_id, find_unique_zone_issuer!(configured, zone_id)]
        end.freeze
        unless zone_map.values.sort == configured.sort
          raise ConfigurationError, "trusted issuers must match the zones in resource_identifiers_by_zone"
        end

        [zone_map.values.freeze, zone_map]
      end

      def find_unique_zone_issuer!(normalized, zone_id)
        matched = normalized.select { |url| URI.parse(url).host&.start_with?("#{zone_id}.") }
        raise ConfigurationError, "cannot uniquely match issuer for zone #{zone_id}" unless matched.length == 1

        matched.first
      rescue URI::InvalidURIError => e
        raise ConfigurationError, "invalid issuer URL: #{e.message}"
      end

      def verify_against(issuers, token, audiences)
        claims = JWTVerifier.new(issuers: issuers, keyring: @keyring, audiences: audiences,
                                 clock: @clock).verify(token)
        audience = claims["aud"]
        claims = claims.merge("aud" => [audience]) if audience.is_a?(String)
        AccessToken.new(token: token, claims: claims)
      end
    end
  end
end
