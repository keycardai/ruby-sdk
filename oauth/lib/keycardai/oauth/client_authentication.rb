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
  end
end
