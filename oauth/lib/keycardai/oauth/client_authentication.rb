# frozen_string_literal: true

module Keycardai
  module OAuth
    # The headers and form fields that authenticate a client on one request
    # to the authorization server. A credential that provides client
    # authentication responds to client_authentication(issuer:, endpoint:)
    # and returns one. The method is optional, so a credential defined
    # outside the SDK keeps working without it.
    #
    # It never includes a grant parameter such as grant_type or
    # subject_token_type. The caller merges it into its own request.
    ClientAuthentication = Data.define(:headers, :params) do
      # @param headers [Hash{String => String}]
      # @param params [Hash{String => String}] form fields
      def initialize(headers: {}, params: {})
        super
      end
    end

    # Internals for operations that authenticate with a credential's client
    # authentication, a client_id and client_secret pair, or a public
    # client_id. Not public API.
    module ClientAuth
      module_function

      # Raise ConfigurationError when credential is set with client_id or
      # client_secret, when credential does not respond to
      # client_authentication, or when neither credential nor a non-empty
      # client_id is set. Call it before any request.
      #
      # @raise [ConfigurationError]
      def validate(credential:, client_id:, client_secret: nil)
        if credential
          given = { "client_id" => client_id, "client_secret" => client_secret }.compact.keys
          raise ConfigurationError, "pass a credential or #{given.join(" and ")}, not both" unless given.empty?
          return if credential.respond_to?(:client_authentication)

          raise ConfigurationError, "#{credential.class} does not provide client authentication"
        end
        return unless client_id.nil? || client_id.empty?

        raise ConfigurationError, "pass a credential or a client_id"
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
    private_constant :ClientAuth
  end
end
