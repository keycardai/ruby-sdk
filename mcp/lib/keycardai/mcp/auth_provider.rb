# frozen_string_literal: true

module Keycardai
  module MCP
    # The delegated-access provider for an MCP server: holds the zone and the
    # application credential, builds the inbound TokenVerifier, and exposes
    # grant middleware plus imperative token exchange. Multi-zone is inferred
    # from a multi-zone credential (the credential is self-describing).
    #
    #   provider = Keycardai::MCP::AuthProvider.new(
    #     zone_url: "https://acme.keycard.cloud",
    #     credential: Keycardai::OAuth::ClientSecret.new(client_id, client_secret),
    #   )
    #   use Keycardai::MCP::RequireBearerAuth, verifier: provider.token_verifier
    #   use provider.grant("https://api.example.com")
    class AuthProvider
      # @param zone_url [String] the zone's issuer URL
      # @param credential [Object, nil] an application credential; a
      #   multi-zone ClientSecret switches the provider to multi-zone
      # @param client_id [String, nil] shared-secret pair alternative
      # @param client_secret [String, nil]
      # @param audiences [String, Array<String>, nil] enforced on inbound tokens
      # @param http_client [#get, #post_form] pluggable transport
      # @param timeout [Numeric, nil]
      def initialize(zone_url:, credential: nil, client_id: nil, client_secret: nil, audiences: nil,
                     http_client: Keycardai::OAuth::HTTP::NetHTTPClient.new, timeout: nil)
        @zone_url = zone_url
        @credential = credential || (client_id ? Keycardai::OAuth::ClientSecret.new(client_id, client_secret) : nil)
        @audiences = audiences
        @http_client = http_client
        @timeout = timeout
        @mutex = Mutex.new
      end

      # The issuers this provider trusts: the zone URL, plus every zone of a
      # multi-zone credential.
      #
      # @return [Array<String>]
      def issuers
        zones = @credential.respond_to?(:multi_zone?) && @credential.multi_zone? ? @credential.issuers : []
        ([@zone_url] + zones).uniq
      end

      # The inbound bearer-token verifier for this provider's zone(s).
      #
      # @return [Keycardai::OAuth::TokenVerifier]
      def token_verifier
        @mutex.synchronize do
          @token_verifier ||= Keycardai::OAuth::TokenVerifier.new(
            issuers: issuers, audiences: @audiences, http_client: @http_client
          )
        end
      end

      # Grant middleware: declare the downstream resources a route needs, and
      # the caller's verified token is exchanged for one token per resource
      # before the handler runs. Results and per-resource errors land on the
      # AccessContext in the Rack env (Keycardai::MCP.access_context); a
      # per-resource failure never aborts the request. Stacked grants merge
      # into one context. A missing verified token is rejected 401 fail-fast.
      #
      # @param resources [String, Array<String>]
      # @param user_identifier [String, #call, nil] impersonation target; a
      #   callable receives the Rack env and returns the user id
      # @param request_scopes [String, Hash{String => String}, nil]
      # @return [Class] a Rack middleware class for `use`
      def grant(resources, user_identifier: nil, request_scopes: nil)
        provider = self
        Class.new(Grant) do
          define_method(:initialize) do |app|
            super(app, provider: provider, resources: Array(resources),
                       user_identifier: user_identifier, request_scopes: request_scopes)
          end
        end
      end

      # Imperative exchange: the caller's token for one token per resource.
      #
      # @return [Keycardai::OAuth::AccessContext]
      def exchange_tokens(subject_token, resources, access_context: Keycardai::OAuth::AccessContext.new,
                          user_identifier: nil, request_scopes: nil, issuer: nil)
        Keycardai::OAuth.exchange_tokens_for_resources(
          client: exchange_client, resources: Array(resources), subject_token: subject_token,
          access_context: access_context, user_identifier: user_identifier,
          request_scopes: request_scopes, issuer: issuer
        )
      end

      # Zone-selected imperative exchange for multi-zone providers.
      #
      # @return [Keycardai::OAuth::AccessContext]
      def exchange_tokens_for_zone(issuer, subject_token, resources, **)
        exchange_tokens(subject_token, resources, issuer: issuer, **)
      end

      private

      def exchange_client
        @mutex.synchronize do
          @exchange_client ||= Keycardai::OAuth::TokenExchangeClient.new(
            issuer: @zone_url, credential: @credential, http_client: @http_client, timeout: @timeout
          )
        end
      end

      # The middleware realizing a grant declaration. Not used directly;
      # constructed through AuthProvider#grant.
      class Grant
        def initialize(app, provider:, resources:, user_identifier:, request_scopes:)
          @app = app
          @provider = provider
          @resources = resources
          @user_identifier = user_identifier
          @request_scopes = request_scopes
        end

        def call(env)
          auth_info = env[ENV_AUTH_INFO]
          return RackSupport.challenge_response(env, status: 401) if auth_info.nil?

          context = env[ENV_ACCESS_CONTEXT] || Keycardai::OAuth::AccessContext.new
          @provider.exchange_tokens(
            auth_info.token, @resources,
            access_context: context, user_identifier: resolve_user(env), request_scopes: @request_scopes
          )
          env[ENV_ACCESS_CONTEXT] = context
          @app.call(env)
        end

        private

        def resolve_user(env)
          @user_identifier.respond_to?(:call) ? @user_identifier.call(env) : @user_identifier
        end
      end
    end
  end
end
