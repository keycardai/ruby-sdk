# frozen_string_literal: true

module Keycardai
  module OAuth
    # Workload-identity credential: authenticates with a platform-signed OIDC
    # token as its client assertion (RFC 7523 over RFC 8693). One generic
    # credential owns the exchange contract; a pluggable identity-token source
    # supplies the platform token, fetched fresh on every request because
    # platforms rotate these tokens. The credential never caches the token; a
    # source may cache internally when the platform contract makes that safe.
    #
    # Holds no shared secret and contributes no Basic header.
    class WorkloadIdentity
      include PrintedForm

      attr_reader :client_id

      # @param source [#identity_token, #call] supplies the platform-signed
      #   OIDC token; a bare callable is accepted
      # @param client_id [String, nil] public ID of the Keycard application
      #   credential this workload authenticates as; sent as the client_id form
      #   parameter on every token request and client authentication when set.
      #   A v2 token credential requires it; a v1 credential rejects it
      # @raise [ConfigurationError] when the source is missing or has neither
      #   an identity_token method nor call
      def initialize(source:, client_id: nil)
        @source = normalize_source(source)
        @client_id = client_id
      end

      # Shows the client ID and the source's identifier. Never calls the
      # source, so it shows no platform token.
      #
      # @return [String]
      def inspect
        "#<#{self.class} client_id=#{@client_id.inspect}, source=#{source_identifier.inspect}>"
      end

      # Assertion-based authentication contributes no Basic header.
      #
      # @param issuer [String, nil] unused; part of the Credential interface
      # @return [nil]
      def authorization_header(issuer: nil)
        nil
      end

      # Build the token-exchange form parameters, fetching a fresh platform
      # token from the source.
      #
      # @param subject_token [String]
      # @param resource [String, nil]
      # @param audience [String, nil]
      # @param scope [String, nil]
      # @param token_endpoint [String, nil] unused; part of the interface
      # @param issuer [String, nil] unused; part of the Credential interface
      # @return [Hash]
      # @raise [WorkloadIdentityRuntimeError] the source failed to produce a token
      def prepare_token_exchange_request(subject_token:, resource: nil, audience: nil, scope: nil,
                                         token_endpoint: nil, issuer: nil)
        {
          "grant_type" => GrantType::TOKEN_EXCHANGE,
          "subject_token" => subject_token,
          "subject_token_type" => TokenType::ACCESS_TOKEN,
          "resource" => resource,
          "audience" => audience,
          "scope" => scope
        }.compact.merge(client_authentication(issuer: issuer, endpoint: token_endpoint).params)
      end

      # Client authentication for one request, as form fields: the source's
      # token as client_assertion, its type, and client_id when configured.
      # The source is called on every request.
      #
      # @param issuer [String, nil] unused; part of the Credential interface
      # @param endpoint [String, nil] unused; the platform fixes the token's
      #   audience
      # @return [ClientAuthentication]
      # @raise [WorkloadIdentityRuntimeError] the source failed to produce a token
      def client_authentication(issuer:, endpoint:)
        ClientAuthentication.new(params: {
          "client_id" => @client_id,
          "client_assertion" => fetch_identity_token,
          "client_assertion_type" => PrivateKeyManager::ASSERTION_TYPE
        }.compact)
      end

      # Raise unless client_id is set. The interactive grants (the code
      # exchange, authenticate, authenticate_from_challenge, refresh and
      # device authorization) need a v2 token credential, which the zone
      # resolves by client_id, so they call this before any request.
      #
      # @return [void]
      # @raise [ConfigurationError] client_id is nil or empty
      def check_client_authentication
        return unless @client_id.nil? || @client_id.empty?

        raise ConfigurationError,
              "WorkloadIdentity: client_id is required for interactive grants " \
              "(the public ID of a v2 token credential)"
      end

      private

      def normalize_source(source)
        return source if source.respond_to?(:identity_token)
        return FunctionTokenSource.new(source) if source.respond_to?(:call)

        raise ConfigurationError, "WorkloadIdentity source must respond to identity_token or call"
      end

      def fetch_identity_token
        token = @source.identity_token
        if token.nil? || token.empty?
          raise WorkloadIdentityRuntimeError.new("identity token source returned an empty token",
                                                 source: source_identifier)
        end

        token
      rescue WorkloadIdentityRuntimeError, WorkloadIdentityConfigurationError
        raise
      rescue StandardError => e
        raise WorkloadIdentityRuntimeError.new("identity token source failed: #{e.message}",
                                               source: source_identifier)
      end

      def source_identifier
        @source.respond_to?(:source_identifier) ? @source.source_identifier : "custom"
      end

      # Adapter making a bare callable usable as an identity-token source.
      class FunctionTokenSource
        def initialize(callable)
          @callable = callable
        end

        def identity_token
          @callable.call
        end

        def source_identifier
          "custom"
        end
      end
    end
  end
end
