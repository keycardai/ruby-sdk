# frozen_string_literal: true

module Keycardai
  module OAuth
    # Static client_id + client_secret credential, authenticating with
    # client_secret_basic (RFC 6749 §2.3.1 / RFC 7617). The simplest
    # credential type, suitable for development and workloads that can safely
    # hold a long-lived secret.
    #
    # Implements the Credential interface: authorization_header(issuer:) plus
    # prepare_token_exchange_request. Never reads environment variables; the
    # caller sources the secret from its own config or secret manager.
    #
    # Single zone:
    #   ClientSecret.new("client_abc", "secret")
    #
    # Multi-zone, keyed by the zone's issuer URL:
    #   ClientSecret.new(
    #     "https://acme.keycard.cloud" => ["client_a", "secret_a"],
    #     "https://beta.keycard.cloud" => ["client_b", "secret_b"],
    #   )
    #
    # A token operation for a zone not in the map fails closed: the credential
    # raises rather than fall back to another zone's secret.
    class ClientSecret
      # @overload initialize(client_id, client_secret)
      # @overload initialize(issuer_map)
      #   @param issuer_map [Hash{String => Array(String, String)}]
      # @raise [ConfigurationError] empty id/secret, or an empty zone map
      def initialize(client_id_or_map, client_secret = nil)
        if client_id_or_map.is_a?(Hash)
          raise ConfigurationError, "multi-zone ClientSecret requires at least one zone" if client_id_or_map.empty?

          @pairs = client_id_or_map.to_h do |issuer, (id, secret)|
            validate_pair(id, secret)
            [issuer.chomp("/"), [id, secret]]
          end
        else
          validate_pair(client_id_or_map, client_secret)
          @pair = [client_id_or_map, client_secret]
        end
      end

      # @return [Boolean] whether this credential holds per-zone pairs
      def multi_zone?
        !@pairs.nil?
      end

      # @return [Array<String>] the issuer URLs this credential can serve
      def issuers
        multi_zone? ? @pairs.keys : []
      end

      # The HTTP Basic Authorization header for a token operation.
      #
      # @param issuer [String, nil] the target zone; required for multi-zone
      # @return [String]
      # @raise [ConfigurationError] multi-zone lookup for an unconfigured zone
      #   (fails closed, never another zone's secret)
      def authorization_header(issuer: nil)
        client_id, client_secret = resolve_pair(issuer)
        HTTP.basic_authorization(client_id, client_secret)
      end

      # Build the token-exchange form parameters. Client authentication rides
      # in the Basic header, never in the body.
      #
      # @param subject_token [String]
      # @param resource [String, nil]
      # @param audience [String, nil]
      # @param scope [String, nil]
      # @param token_endpoint [String, nil] unused; part of the interface
      # @param issuer [String, nil] unused here; auth resolution is per-header
      # @return [Hash]
      def prepare_token_exchange_request(subject_token:, resource: nil, audience: nil, scope: nil,
                                         token_endpoint: nil, issuer: nil)
        {
          "grant_type" => GrantType::TOKEN_EXCHANGE,
          "subject_token" => subject_token,
          "subject_token_type" => TokenType::ACCESS_TOKEN,
          "resource" => resource,
          "audience" => audience,
          "scope" => scope
        }.compact
      end

      private

      def validate_pair(client_id, client_secret)
        return unless client_id.nil? || client_id.empty? || client_secret.nil? || client_secret.empty?

        raise ConfigurationError, "ClientSecret requires a non-empty client_id and client_secret"
      end

      def resolve_pair(issuer)
        return @pair unless multi_zone?
        raise ConfigurationError, "multi-zone ClientSecret requires an issuer to resolve credentials" if issuer.nil?

        @pairs[issuer.chomp("/")] ||
          raise(ConfigurationError, "no credentials configured for zone #{issuer}")
      end
    end
  end
end
