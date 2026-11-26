# frozen_string_literal: true

module Keycardai
  module OAuth
    # Prepared exchange parameters retain their Hash API and wire values.
    class TokenExchangeForm < Hash
      include PrintedForm

      def self.build(subject_token:, resource:, audience:, scope:, authentication: {})
        params = {
          "grant_type" => GrantType::TOKEN_EXCHANGE,
          "subject_token" => subject_token,
          "subject_token_type" => TokenType::ACCESS_TOKEN,
          "resource" => resource,
          "audience" => audience,
          "scope" => scope
        }
        self[params.compact.merge(authentication)]
      end

      def inspect
        to_h.except("subject_token", "actor_token", "client_assertion", "client_secret").inspect
      end
    end
    private_constant :TokenExchangeForm
  end
end
