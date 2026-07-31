# frozen_string_literal: true

module Keycardai
  # The delegated-access orchestration that feeds an AccessContext.
  module OAuth
    # Exchange a subject token for tokens targeting multiple resources,
    # recording each success or failure on an AccessContext. Non-throwing by
    # design: per-resource failures land on the context so a partial-success
    # flow can proceed. When user_identifier is set, each exchange is an
    # impersonation instead of a subject-token exchange.
    #
    # @param client [TokenExchangeClient] carries the credential and zone
    # @param resources [Array<String>] the target resources
    # @param subject_token [String, nil] the inbound token being delegated;
    #   required unless user_identifier is given
    # @param access_context [AccessContext] the container to populate
    # @param user_identifier [String, nil] impersonation target
    # @param request_scopes [String, Hash{String => String}, nil] scopes for
    #   every exchange, or a per-resource map
    # @param issuer [String, nil] per-call zone selection
    # @return [AccessContext]
    def self.exchange_tokens_for_resources(client:, resources:, subject_token: nil,
                                           access_context: AccessContext.new, user_identifier: nil,
                                           request_scopes: nil, issuer: nil)
      if subject_token.nil? && user_identifier.nil?
        raise ArgumentError, "subject_token is required unless user_identifier is given"
      end

      resources.each do |resource|
        scope = request_scopes.is_a?(Hash) ? request_scopes[resource] : request_scopes
        token = ExchangeTokens.exchange_one(client: client, resource: resource, subject_token: subject_token,
                                            user_identifier: user_identifier, scope: scope, issuer: issuer)
        access_context.set_token(resource, token)
      rescue Keycardai::Error => e
        access_context.set_resource_error(resource, e)
      end
      access_context
    end

    # Internals of exchange_tokens_for_resources. Not public API.
    module ExchangeTokens
      module_function

      def exchange_one(client:, resource:, subject_token:, user_identifier:, scope:, issuer:)
        if user_identifier
          client.impersonate(user_identifier: user_identifier, resource: resource, scope: scope, issuer: issuer)
        else
          client.exchange_token(subject_token: subject_token, resource: resource, scope: scope, issuer: issuer)
        end
      end
    end
  end
end
