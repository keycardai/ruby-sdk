# frozen_string_literal: true

module Keycardai
  # Root of the Keycard error taxonomy. Every error raised by any Keycard gem
  # is a subclass, so `rescue Keycardai::Error` catches the whole family.
  class Error < StandardError; end

  module OAuth
    # Invalid configuration detected at construction time: missing credential,
    # empty issuer list, an algorithm the verifier does not implement.
    class ConfigurationError < Keycardai::Error; end

    # A transport-level failure (DNS, TLS, timeout) wrapping the underlying
    # exception as +cause+.
    class NetworkError < Keycardai::Error; end

    # A non-2xx HTTP response. Carries the status code and response body.
    class HTTPError < Keycardai::Error
      # @return [Integer]
      attr_reader :status
      # @return [String]
      attr_reader :body

      def initialize(message, status:, body: "")
        super(message)
        @status = status
        @body = body
      end
    end

    # A bearer token failed verification: malformed, disallowed algorithm,
    # untrusted issuer, missing required claim, expired, audience mismatch,
    # missing kid, or bad signature. One category for every rejection, so
    # callers handle all verification failures the same way.
    class InvalidTokenError < Keycardai::Error; end

    # Base class for JWKS key-resolution failures.
    class JWKSError < Keycardai::Error; end

    # Authorization server discovery failed or its metadata carries no
    # +jwks_uri+.
    class JWKSDiscoveryError < JWKSError; end

    # The discovered +jwks_uri+ does not share the issuer's origin. Rejected
    # before any key fetch.
    class JWKSUriValidationError < JWKSError; end

    # The JWKS endpoint returned a non-2xx response or could not be reached.
    class JWKSFetchError < JWKSError; end

    # The token's +kid+ is not present in the issuer's fetched JWKS.
    class JWKSKeyNotFoundError < JWKSError; end
  end
end
