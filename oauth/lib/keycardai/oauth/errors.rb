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

    # An OAuth error response from the authorization server (RFC 6749 §5.2).
    # Carries the wire error code plus the optional description and URI.
    class OAuthError < HTTPError
      # @return [String] the OAuth error code (e.g. invalid_grant)
      attr_reader :error
      # @return [String, nil]
      attr_reader :error_description
      # @return [String, nil]
      attr_reader :error_uri

      def initialize(message, error:, status:, body: "", error_description: nil, error_uri: nil)
        super(message, status: status, body: body)
        @error = error
        @error_description = error_description
        @error_uri = error_uri
      end
    end

    # The server's response violates the protocol contract: metadata with a
    # mismatched or missing issuer, a token response with no access token.
    # The +code+ discriminates the case (issuer_mismatch, invalid_metadata,
    # invalid_response).
    class ProtocolError < Keycardai::Error
      # @return [String]
      attr_reader :code

      def initialize(message, code:)
        super(message)
        @code = code
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

    # The user did not complete the browser redirect within the loopback
    # flow's callback timeout.
    class InteractionTimeoutError < Keycardai::Error; end

    # Raised by AccessContext#access when a token cannot be handed out. The
    # error_type identifies the condition: global_error (a context-wide error
    # is set), resource_error (the named resource's exchange failed), or
    # missing_token (the resource was never granted). For missing_token,
    # available_resources lists what was granted.
    class ResourceAccessError < Keycardai::Error
      # @return [String]
      attr_reader :resource
      # @return [String] global_error | resource_error | missing_token
      attr_reader :error_type
      # @return [Array<String>]
      attr_reader :available_resources
      # @return [Object, nil] the recorded upstream error, when one exists
      attr_reader :error_details

      def initialize(message, resource:, error_type:, available_resources: [], error_details: nil)
        super(message)
        @resource = resource
        @error_type = error_type
        @available_resources = available_resources
        @error_details = error_details
      end
    end

    # A workload-identity source is misconfigured at construction: missing
    # token file, no discovery env var set, missing required audience.
    # Carries the source identifier (file, gcp-metadata, fly, custom).
    class WorkloadIdentityConfigurationError < ConfigurationError
      # @return [String]
      attr_reader :source

      def initialize(message, source:)
        super(message)
        @source = source
      end
    end

    # A workload-identity source failed at request time: file unreadable or
    # empty, endpoint unreachable, non-200 response, empty token. Carries the
    # source identifier and preserves the underlying cause.
    class WorkloadIdentityRuntimeError < Keycardai::Error
      # @return [String]
      attr_reader :source

      def initialize(message, source:)
        super(message)
        @source = source
      end
    end
  end
end
