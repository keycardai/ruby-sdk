# frozen_string_literal: true

module Keycardai
  module MCP
    # The delegated-access provider for an MCP server: holds the zone and the
    # application credential, builds the inbound TokenVerifier and MetadataApp,
    # and exposes grant middleware plus imperative token exchange. Multi-zone is
    # inferred from a multi-zone credential (the credential is self-describing).
    #
    #   provider = Keycardai::MCP::AuthProvider.new(
    #     zone_url: "https://acme.keycard.cloud",
    #     resource_identifier: "https://api.example.com/mcp",
    #     credential: Keycardai::OAuth::ClientSecret.new(client_id, client_secret),
    #   )
    #   use Keycardai::MCP::RequireBearerAuth, verifier: provider.token_verifier
    #   use provider.grant("https://api.example.com")
    class AuthProvider
      # @return [Keycardai::OAuth::ResourceBinding]
      attr_reader :resource_binding

      # @param zone_url [String] the zone's issuer URL, or base issuer URL in zone modes
      # @param credential [Object, nil] an application credential; a
      #   multi-zone ClientSecret switches the provider to multi-zone
      # @param client_id [String, nil] shared-secret pair alternative
      # @param client_secret [String, nil]
      # @param resource_identifier [String, nil] exact HTTP(S) URL or URN in single-resource mode
      # @param resource_identifiers_by_zone [Hash{String => String}, nil] zone ID to identifier map
      # @param multi_resource [Boolean] explicit multi-resource or shared-discovery opt-in
      # @param allow_any_audience [Boolean] explicit opt-out from audience validation
      # @param audiences [String, Array<String>, nil] enforced on inbound tokens
      # @param http_client [#get, #post_form] pluggable transport
      # @param timeout [Numeric, nil]
      # @raise [Keycardai::OAuth::ConfigurationError] invalid or conflicting mode options
      def initialize(zone_url:, credential: nil, client_id: nil, client_secret: nil,
                     resource_identifier: nil, resource_identifiers_by_zone: nil,
                     multi_resource: false, allow_any_audience: false, audiences: nil,
                     http_client: Keycardai::OAuth::HTTP::NetHTTPClient.new, timeout: nil)
        @resource_binding = Keycardai::OAuth::ResourceBinding.resolve(
          resource_identifier: resource_identifier,
          resource_identifiers_by_zone: resource_identifiers_by_zone,
          multi_resource: multi_resource,
          allow_any_audience: allow_any_audience,
          audiences: audiences,
          require_issuer_for_zones: true,
          base_issuer: zone_url,
          component: "Keycardai::MCP::AuthProvider"
        )
        @zone_url = zone_url
        @credential = credential || (client_id ? Keycardai::OAuth::ClientSecret.new(client_id, client_secret) : nil)
        @http_client = http_client
        @timeout = timeout
        @mutex = Mutex.new
      end

      # Shows the zone URL, the audiences, and the credential's class.
      #
      # @return [String]
      def inspect
        credential = @credential.nil? ? "nil" : @credential.class.name || @credential.class.to_s
        "#<#{self.class} zone_url=#{@zone_url.inspect}, audiences=#{@audiences.inspect}, credential=#{credential}>"
      end
      alias to_s inspect

      # Used by pp.
      def pretty_print(printer)
        printer.text(inspect)
      end

      # The issuers this provider trusts: the zone URL, plus every zone of a
      # multi-zone credential or configured zone resource map.
      #
      # @return [Array<String>]
      def issuers
        return @resource_binding.zone_issuers(@zone_url).values if @resource_binding.zone_mode?

        zones = @credential.respond_to?(:multi_zone?) && @credential.multi_zone? ? @credential.issuers : []
        ([@zone_url] + zones).uniq
      end

      # The inbound bearer-token verifier for this provider's zone(s).
      #
      # @return [Keycardai::OAuth::TokenVerifier]
      def token_verifier
        @mutex.synchronize do
          @token_verifier ||= Keycardai::OAuth::TokenVerifier.new(
            issuer: @zone_url,
            issuers: @resource_binding.zone_mode? ? nil : issuers,
            resource_binding: @resource_binding,
            http_client: @http_client
          )
        end
      end

      # Build a MetadataApp sharing this provider's zone URL and resource binding.
      #
      # @return [Keycardai::MCP::MetadataApp]
      def metadata_app(**)
        MetadataApp.new(
          issuer: @zone_url,
          resource_binding: @resource_binding,
          http_client: @http_client,
          **
        )
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
          if auth_info.nil?
            binding = env[ENV_RESOURCE_BINDING] || @provider.resource_binding
            return RackSupport.challenge_response(env, status: 401, binding: binding, zone_id: env[ENV_ZONE_ID])
          end

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
