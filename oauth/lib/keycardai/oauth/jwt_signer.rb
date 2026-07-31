# frozen_string_literal: true

require "jwt"

module Keycardai
  module OAuth
    # Signs compact JWTs (RFC 7519) with RS256, the baseline algorithm the SDK
    # family uses for private_key_jwt client assertions (RFC 7523) and signed
    # access tokens (RFC 9068).
    #
    # The signer writes the JWT header ({alg, kid}) from its construction-time
    # key material. Claims are signed verbatim: temporal claims (exp, iat, nbf)
    # come from the caller and the signer does not invent an expiry. When the
    # claims omit iss and the signer carries an issuer, iss is filled in; a
    # caller-supplied iss is preserved.
    class JWTSigner
      ALGORITHM = "RS256"

      # @param key [OpenSSL::PKey::RSA] the RSA private signing key
      # @param kid [String] key id written to the JWT header
      # @param issuer [String, nil] default iss, applied only when claims omit it
      # @raise [ConfigurationError] when the key is not an RSA private key
      def initialize(key:, kid:, issuer: nil)
        unless key.is_a?(OpenSSL::PKey::RSA) && key.private?
          raise ConfigurationError, "JWTSigner requires an RSA private key"
        end
        raise ConfigurationError, "JWTSigner requires a kid" if kid.nil? || kid.empty?

        @key = key
        @kid = kid
        @issuer = issuer
      end

      # Sign a claim set into a compact JWS (header.payload.signature).
      #
      # @param claims [Hash] payload claims; string or symbol keys
      # @return [String] the signed compact JWT
      def sign(claims)
        payload = claims.transform_keys(&:to_s)
        payload["iss"] = @issuer if @issuer && !payload.key?("iss")
        JWT.encode(payload, @key, ALGORITHM, { "kid" => @kid })
      end
    end
  end
end
