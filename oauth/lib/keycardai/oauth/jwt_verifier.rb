# frozen_string_literal: true

require "json"
require "openssl"

module Keycardai
  module OAuth
    # Verifies compact JWTs (RFC 7519) against the RFC 9068 access-token
    # profile, fail-closed. Cheap policy checks (algorithm, trusted issuer,
    # required claims, expiry, audience, kid) run before any key resolution,
    # so a token carrying an attacker-controlled iss never drives key lookup
    # or network I/O. Verification keys are resolved by (issuer, kid) through
    # the injected keyring (see JWKSKeyring).
    #
    # Every rejection raises InvalidTokenError; misconfiguration raises
    # ConfigurationError at construction.
    class JWTVerifier
      SUPPORTED_ALGORITHMS = ["RS256"].freeze
      REQUIRED_CLAIMS = %w[iss sub aud exp iat client_id].freeze

      # @param issuers [String, Array<String>] trusted-issuer allowlist
      # @param keyring [#key] resolves a verification key for (issuer, kid)
      # @param audiences [String, Array<String>, nil] when set, the token's aud
      #   must intersect this set
      # @param algorithms [Array<String>] allowed alg header values
      # @param clock_skew [Numeric] leeway in seconds applied to exp and nbf
      # @param clock [#call] returns the current Time; override in tests
      # @raise [ConfigurationError] no trusted issuer, or an algorithm the
      #   verifier does not implement
      def initialize(issuers:, keyring:, audiences: nil, algorithms: SUPPORTED_ALGORITHMS,
                     clock_skew: 0, clock: -> { Time.now })
        @issuers = Array(issuers).reject { |issuer| issuer.nil? || issuer.empty? }
        raise ConfigurationError, "JWTVerifier requires at least one trusted issuer" if @issuers.empty?

        unimplemented = Array(algorithms) - SUPPORTED_ALGORITHMS
        raise ConfigurationError, "unimplemented algorithms: #{unimplemented.join(", ")}" unless unimplemented.empty?

        @keyring = keyring
        @audiences = audiences.nil? ? nil : Array(audiences)
        @algorithms = Array(algorithms)
        @clock_skew = clock_skew
        @clock = clock
      end

      # Verify a compact JWT and return its claim set.
      #
      # @param token [String]
      # @return [Hash] the verified claims, string-keyed
      # @raise [InvalidTokenError] on any verification failure
      # @raise [JWKSError] when key resolution fails (see JWKSKeyring)
      def verify(token)
        header, claims, signature, signing_input = decode_parts(token)
        check_algorithm(header)
        check_issuer(claims)
        check_required_claims(claims)
        check_temporal(claims)
        check_audience(claims)
        kid = header["kid"]
        raise InvalidTokenError, "token header has no kid" if kid.nil? || kid.empty?

        key = @keyring.key(claims["iss"], kid)
        check_signature(key, signature, signing_input)
        claims
      end

      private

      def decode_parts(token)
        parts = String(token).split(".")
        raise InvalidTokenError, "token is not a three-part compact JWT" unless parts.length == 3

        header = decode_json_segment(parts[0], "header")
        claims = decode_json_segment(parts[1], "payload")
        signature = decode_segment(parts[2], "signature")
        [header, claims, signature, parts[0..1].join(".")]
      end

      def decode_segment(segment, name)
        padded = segment.tr("-_", "+/")
        padded += "=" * ((4 - (padded.length % 4)) % 4)
        padded.unpack1("m0")
      rescue ArgumentError
        raise InvalidTokenError, "token #{name} does not decode"
      end

      def decode_json_segment(segment, name)
        document = JSON.parse(decode_segment(segment, name))
        raise InvalidTokenError, "token #{name} is not a JSON object" unless document.is_a?(Hash)

        document
      rescue JSON::ParserError
        raise InvalidTokenError, "token #{name} is not valid JSON"
      end

      def check_algorithm(header)
        algorithm = header["alg"]
        raise InvalidTokenError, "token alg is missing" if algorithm.nil? || algorithm.empty?
        raise InvalidTokenError, "token alg none is rejected" if algorithm.casecmp("none").zero?
        raise InvalidTokenError, "token alg #{algorithm} is not allowed" unless @algorithms.include?(algorithm)
      end

      def check_issuer(claims)
        issuer = claims["iss"]
        return if issuer.is_a?(String) && @issuers.include?(issuer)

        raise InvalidTokenError, "token issuer is not trusted"
      end

      def check_required_claims(claims)
        missing = REQUIRED_CLAIMS.reject { |name| claims.key?(name) }
        raise InvalidTokenError, "token is missing required claims: #{missing.join(", ")}" unless missing.empty?
        return if claims["exp"].is_a?(Numeric) && claims["exp"].to_f.finite?

        raise InvalidTokenError,
              "token exp is not a number"
      end

      def check_temporal(claims)
        current = @clock.call.to_i
        raise InvalidTokenError, "token is expired" if current > claims["exp"] + @clock_skew

        not_before = claims["nbf"]
        return unless not_before.is_a?(Numeric)
        raise InvalidTokenError, "token is not yet valid" if current < not_before - @clock_skew
      end

      def check_audience(claims)
        return if @audiences.nil?

        token_audiences = Array(claims["aud"])
        return if token_audiences.intersect?(@audiences)

        raise InvalidTokenError, "token audience does not match"
      end

      def check_signature(key, signature, signing_input)
        # RS256: RSASSA-PKCS1-v1_5 with SHA-256.
        return if key.verify(OpenSSL::Digest.new("SHA256"), signature, signing_input)

        raise InvalidTokenError, "token signature does not validate"
      rescue OpenSSL::PKey::PKeyError
        raise InvalidTokenError, "token signature does not validate"
      end
    end
  end
end
