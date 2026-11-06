# frozen_string_literal: true

module Keycardai
  module OAuth
    # The headers and form fields that authenticate a client on one request
    # to the authorization server. Credentials return one from
    # client_authentication(issuer:, endpoint:). It never includes a grant
    # parameter such as grant_type or subject_token_type; the caller merges
    # it into its own request.
    ClientAuthentication = Data.define(:headers, :params) do
      # @param headers [Hash{String => String}]
      # @param params [Hash{String => String}] form fields
      def initialize(headers: {}, params: {})
        super
      end
    end

    # Internals for operations that authenticate with a credential's client
    # authentication, a client_id/client_secret pair, or a public client_id.
    # Not public API.
    module ClientAuth
      module_function

      # Raise unless exactly one of credential and client_id is set, and the
      # credential provides client authentication. Runs before any request.
      #
      # Client authentication is optional on a credential. Detect it with
      # respond_to?(:client_authentication), so credentials defined outside
      # the SDK keep working for the operations that do not need it.
      #
      # @raise [ConfigurationError]
      def validate(credential:, client_id:, client_secret: nil)
        if credential
          raise ConfigurationError, "provide a credential or a client_id, not both" if client_id || client_secret
          return if credential.respond_to?(:client_authentication)

          raise ConfigurationError, "#{credential.class} does not provide client authentication"
        end
        return unless client_id.nil? || client_id.empty?

        raise ConfigurationError, "provide a credential or a client_id"
      end

      # Add client authentication to a request. A credential adds what its
      # client_authentication returns for this endpoint. A client_secret adds
      # an HTTP Basic header. A public client adds client_id to the body.
      #
      # @param params [Array<Array(String, String)>] form fields as pairs, so
      #   repeated keys such as resource survive
      # @param headers [Hash{String => String}]
      # @return [Array(Array<Array(String, String)>, Hash{String => String})]
      def apply(params, headers, issuer:, endpoint:, credential: nil, client_id: nil, client_secret: nil)
        if credential
          auth = credential.client_authentication(issuer: issuer, endpoint: endpoint)
          [params + auth.params.to_a, headers.merge(auth.headers)]
        elsif client_secret
          [params, headers.merge("Authorization" => HTTP.basic_authorization(client_id, client_secret))]
        else
          [params + [["client_id", client_id]], headers]
        end
      end
    end
  end
end
