# frozen_string_literal: true

require "openssl"
require "securerandom"

module Keycardai
  module OAuth
    # PKCE primitives (RFC 7636): generate a code verifier and derive its
    # challenge. S256 is the default and the method public clients should use;
    # plain is RFC-permitted but not recommended.
    module PKCE
      VERIFIER_CHARSET = [*"A".."Z", *"a".."z", *"0".."9", "-", ".", "_", "~"].freeze
      DEFAULT_VERIFIER_LENGTH = 128
      METHODS = %w[S256 plain].freeze

      # A verifier with its derived challenge.
      Pair = Data.define(:code_verifier, :code_challenge, :code_challenge_method)

      module_function

      # Generate a cryptographically random verifier (RFC 7636 §4.1).
      #
      # @param length [Integer] 43 to 128
      # @return [String]
      def generate_code_verifier(length: DEFAULT_VERIFIER_LENGTH)
        raise ArgumentError, "verifier length must be between 43 and 128, got #{length}" unless (43..128).cover?(length)

        Array.new(length) { VERIFIER_CHARSET[SecureRandom.random_number(VERIFIER_CHARSET.length)] }.join
      end

      # Derive the challenge for a verifier (RFC 7636 §4.2).
      #
      # @param code_verifier [String]
      # @param method ["S256", "plain"]
      # @return [String]
      def generate_code_challenge(code_verifier, method: "S256")
        case method
        when "S256"
          [OpenSSL::Digest.digest("SHA256", code_verifier)].pack("m0").tr("+/", "-_").delete("=")
        when "plain"
          code_verifier
        else
          raise ArgumentError, "unsupported code_challenge_method #{method.inspect}"
        end
      end

      # Generate a verifier and its challenge together.
      #
      # @param length [Integer] verifier length, 43 to 128
      # @param method ["S256", "plain"]
      # @return [Pair]
      def generate_pair(length: DEFAULT_VERIFIER_LENGTH, method: "S256")
        code_verifier = generate_code_verifier(length: length)
        Pair.new(
          code_verifier: code_verifier,
          code_challenge: generate_code_challenge(code_verifier, method: method),
          code_challenge_method: method
        )
      end
    end
  end
end
