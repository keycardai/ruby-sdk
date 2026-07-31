# frozen_string_literal: true

require "securerandom"

module Keycardai
  module OAuth
    # private_key_jwt credential (RFC 7523) with auto-managed asymmetric keys:
    # generates and persists an RSA-2048 keypair on first use, signs a
    # short-lived client assertion on every token request, and exposes the
    # public JWKS for the authorization server to verify. The recommended
    # credential for production workloads that can persist a keypair; the
    # private key never leaves the workload.
    #
    # Holds no shared secret and contributes no Basic header. Never reads
    # environment variables; the caller supplies storage configuration.
    class WebIdentity
      # @param client_id [String] the registered OAuth client id, signed as
      #   the assertion's iss and sub
      # @param server_name [String, nil] sanitized into the key id when no
      #   key_id is given
      # @param key_id [String, nil] explicit key id (the JWT kid); otherwise
      #   derived from server_name, otherwise a generated UUID
      # @param storage [#load, #store, nil] pluggable keypair storage
      # @param storage_dir [String, nil] directory for the default file store
      # @param clock [#call] returns the current Time; override in tests
      # @raise [ConfigurationError] missing client_id
      def initialize(client_id:, server_name: nil, key_id: nil, storage: nil, storage_dir: nil,
                     clock: -> { Time.now })
        raise ConfigurationError, "WebIdentity requires a client_id" if client_id.nil? || client_id.empty?

        @client_id = client_id
        storage ||= FilePrivateKeyStorage.new(dir: storage_dir || FilePrivateKeyStorage::DEFAULT_DIR)
        @key_manager = PrivateKeyManager.new(
          key_id: key_id || sanitize(server_name) || SecureRandom.uuid,
          storage: storage, clock: clock
        )
      end

      # @return [String] the key id used as the assertion's kid
      def key_id
        @key_manager.key_id
      end

      # Assertion-based authentication contributes no Basic header.
      #
      # @param issuer [String, nil] unused; part of the Credential interface
      # @return [nil]
      def authorization_header(issuer: nil)
        nil
      end

      # Build the token-exchange form parameters, signing a fresh client
      # assertion for this request.
      #
      # @param subject_token [String]
      # @param token_endpoint [String] the assertion's audience
      # @param resource [String, nil]
      # @param audience [String, nil]
      # @param scope [String, nil]
      # @param issuer [String, nil] unused; part of the Credential interface
      # @return [Hash]
      # @raise [ConfigurationError] when token_endpoint is missing
      def prepare_token_exchange_request(subject_token:, token_endpoint: nil, resource: nil,
                                         audience: nil, scope: nil, issuer: nil)
        if token_endpoint.nil? || token_endpoint.empty?
          raise ConfigurationError, "WebIdentity requires the token_endpoint as the assertion audience"
        end

        {
          "grant_type" => GrantType::TOKEN_EXCHANGE,
          "subject_token" => subject_token,
          "subject_token_type" => TokenType::ACCESS_TOKEN,
          "resource" => resource,
          "audience" => audience,
          "scope" => scope,
          "client_assertion" => @key_manager.create_client_assertion(client_id: @client_id,
                                                                     audience: token_endpoint),
          "client_assertion_type" => PrivateKeyManager::ASSERTION_TYPE
        }.compact
      end

      # The public JWKS the authorization server verifies assertions against.
      #
      # @return [Hash] {"keys" => [...]}
      def public_jwks
        @key_manager.public_jwks
      end

      # The conventional URL where this workload serves its public JWKS.
      #
      # @param base_url [String] the workload's public base URL
      # @return [String]
      def client_jwks_url(base_url)
        "#{base_url.chomp("/")}/.well-known/jwks.json"
      end

      private

      def sanitize(server_name)
        return nil if server_name.nil? || server_name.empty?

        server_name.downcase.gsub(/[^a-z0-9]+/, "-").gsub(/\A-+|-+\z/, "")
      end
    end
  end
end
