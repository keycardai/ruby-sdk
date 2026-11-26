# frozen_string_literal: true

require_relative "bearer_introspection"

module Keycardai
  module MCP
    # Rack middleware verifying the Authorization bearer token against the
    # zone's JWKS. Fail-closed: unauthenticated requests are rejected with an
    # RFC 6750 challenge, and never reach the app. On success the verified
    # AccessToken is stored in the Rack env (Keycardai::MCP.auth_info).
    #
    #   use Keycardai::MCP::RequireBearerAuth,
    #       verifier: Keycardai::OAuth::TokenVerifier.new(
    #         issuers: zone_url,
    #         resource_identifier: "https://api.example.com/mcp"
    #       ),
    #       required_scopes: ["mcp:tools"]
    #
    # Route-level gating is this same middleware applied per route with a
    # required_scopes set; every configured scope must be present (all-of), a
    # missing one yielding 403 insufficient_scope.
    class RequireBearerAuth
      # @return [Keycardai::OAuth::ResourceBinding, nil]
      attr_reader :resource_binding

      # @param app [#call] the downstream Rack app
      # @param verifier [#verify_token, nil] a TokenVerifier
      # @param zone_url [String, nil] zone issuer URL (builds a TokenVerifier when verifier is omitted)
      # @param issuer [String, nil] alias for zone_url / base issuer for zone modes
      # @param required_scopes [Array<String>, String, nil] all-of scope set
      # @param resource_identifier [String, nil] exact HTTP(S) URL or URN in single-resource mode
      # @param resource_identifiers_by_zone [Hash{String => String}, nil] zone ID to identifier map
      # @param multi_resource [Boolean] explicit multi-resource or shared-discovery opt-in
      # @param allow_any_audience [Boolean] explicit opt-out from audience validation
      # @param audiences [String, Array<String>, nil] accepted audiences in multi_resource or legacy mode
      # @param zone_resolver [#call, nil] request-only zone selector `(env) -> zone_id` for per-zone mode
      # @param http_client [#get, #post_form, nil] transport for an internally constructed verifier and introspection
      # @param introspect [Boolean] check token status after local verification and scope checks
      # @param credential [#client_authentication, nil] credential of the Application that owns the Resource
      # @param timeout [Numeric, nil] introspection HTTP request timeout in seconds
      # @raise [Keycardai::OAuth::ConfigurationError] invalid mode, missing verifier, or verifier mismatch
      def initialize(app, verifier: nil, zone_url: nil, issuer: nil, required_scopes: nil,
                     resource_identifier: nil, resource_identifiers_by_zone: nil,
                     multi_resource: false, allow_any_audience: false, audiences: nil,
                     zone_resolver: nil, http_client: nil, introspect: false, credential: nil, timeout: nil)
        @app = app
        @required_scopes = Array(required_scopes)
        @zone_resolver = zone_resolver
        @verifier, @resource_binding = resolve_verifier_and_binding(
          verifier: verifier, base_issuer: issuer || zone_url, http_client: http_client,
          mode_options: {
            resource_identifier: resource_identifier, resource_identifiers_by_zone: resource_identifiers_by_zone,
            multi_resource: multi_resource, allow_any_audience: allow_any_audience, audiences: audiences
          }
        )
        validate_zone_resolver! if @resource_binding&.per_zone?
        return unless introspect

        @introspection = BearerIntrospection.new(verifier: @verifier, credential: credential, http_client: http_client,
                                                 timeout: timeout)
      end

      def call(env)
        upstream = env[ENV_RESOURCE_BINDING]
        binding = @resource_binding || upstream
        env[ENV_RESOURCE_BINDING] = binding if binding
        if env[ENV_AUTH_INFO] && reuse_upstream_auth?(upstream)
          return enforce_scopes(env, env[ENV_AUTH_INFO], binding, env[ENV_ZONE_ID])
        end
        return call_per_zone(env, binding) if binding&.per_zone?

        authenticate_request(env, binding, nil)
      end

      private

      def call_per_zone(env, binding)
        zone_id = @zone_resolver ? @zone_resolver.call(env) : env[ENV_ZONE_ID]
        unless zone_id && binding.zone_identifiers.key?(zone_id)
          return RackSupport.challenge_response(env, status: 401, binding: binding, include_metadata: false)
        end

        authenticate_request(env, binding, zone_id)
      end

      # The gate reuses upstream auth only for a compatible binding and when
      # introspection does not need the issuer verified by this gate.
      def reuse_upstream_auth?(upstream)
        !@introspection && (@resource_binding.nil? || (upstream && @resource_binding.compatible_with?(upstream)))
      end

      def authenticate_request(env, binding, zone_id)
        header = env["HTTP_AUTHORIZATION"]
        if header.nil? || header.empty?
          return RackSupport.challenge_response(env, status: 401, binding: binding, zone_id: zone_id)
        end

        parts = header.split
        return [400, { "content-type" => "application/json" }, ['{"error":"invalid_request"}']] if parts.length != 2

        scheme, token = parts
        unless scheme.casecmp("bearer").zero?
          return RackSupport.challenge_response(env, status: 401, error: "invalid_token",
                                                     description: "unsupported authorization scheme",
                                                     binding: binding, zone_id: zone_id)
        end

        authorize(env, token, binding, zone_id)
      end

      def authorize(env, token, binding, zone_id)
        upstream_issuer = env[ENV_AUTH_INFO]&.issuer if zone_id == env[ENV_ZONE_ID]
        access_token, failure = verify(token, zone_id, upstream_issuer)
        if failure.nil? && !RackSupport.audience_matches?(access_token, binding, zone_id)
          failure = "token audience does not match the resource"
        end
        if failure == :unavailable
          return RackSupport.json_response({ "error" => "temporarily_unavailable" }, status: 503)
        end
        if failure
          return RackSupport.challenge_response(env, status: 401, error: "invalid_token",
                                                     description: failure, binding: binding, zone_id: zone_id)
        end

        enforce_scopes(env, access_token, binding, zone_id)
      end

      def enforce_scopes(env, access_token, binding, zone_id)
        missing = @required_scopes - access_token.scopes
        unless missing.empty?
          return RackSupport.challenge_response(env, status: 403, error: "insufficient_scope",
                                                     description: "missing required scopes: #{missing.join(" ")}",
                                                     binding: binding, zone_id: zone_id)
        end

        introspection_failure = @introspection&.failure_response(env, access_token, binding, zone_id)
        return introspection_failure if introspection_failure

        env[ENV_ZONE_ID] = zone_id if zone_id
        env[ENV_AUTH_INFO] = access_token
        @app.call(env)
      end

      UNAVAILABLE_ERRORS = [
        Keycardai::OAuth::JWKSFetchError, Keycardai::OAuth::JWKSDiscoveryError,
        Keycardai::OAuth::HTTPError, Keycardai::OAuth::NetworkError
      ].freeze
      private_constant :UNAVAILABLE_ERRORS

      def verify(token, zone_id, upstream_issuer)
        pinned = zone_id && (@resource_binding || @verifier.respond_to?(:verify_token_for_zone))
        return [@verifier.verify_token_for_zone(token, zone_id), nil] if pinned

        token_info = @verifier.verify_token(token)
        trusted_issuer = zone_id.nil? || token_info.issuer == upstream_issuer
        trusted_issuer ? [token_info, nil] : [nil, "token issuer does not match the selected zone"]
      rescue *UNAVAILABLE_ERRORS
        [nil, :unavailable]
      rescue Keycardai::Error => e
        [nil, e.message]
      end

      def resolve_verifier_and_binding(verifier:, base_issuer:, http_client:, mode_options:)
        has_mode_opts = mode_options.values.any? { |v| v && v != false }
        return build_verifier(base_issuer, http_client, mode_options) if verifier.nil?
        return [verifier, verifier_binding(verifier)] unless has_mode_opts

        local = Keycardai::OAuth::ResourceBinding.resolve(
          **mode_options,
          warn_legacy: !verifier.respond_to?(:resource_binding),
          component: "Keycardai::MCP::RequireBearerAuth"
        )
        check_verifier_compatibility!(verifier, local)
        [verifier, local]
      end

      def build_verifier(base_issuer, http_client, mode_options)
        if base_issuer.nil? || base_issuer.empty?
          raise Keycardai::OAuth::ConfigurationError, "RequireBearerAuth requires a verifier"
        end

        binding = Keycardai::OAuth::ResourceBinding.resolve(
          **mode_options, component: "Keycardai::MCP::RequireBearerAuth"
        )
        client = http_client || Keycardai::OAuth::HTTP::NetHTTPClient.new
        verifier = Keycardai::OAuth::TokenVerifier.new(
          issuer: base_issuer, resource_binding: binding, http_client: client
        )
        [verifier, binding]
      end

      def verifier_binding(verifier)
        verifier.respond_to?(:resource_binding) ? verifier.resource_binding : nil
      end

      def check_verifier_compatibility!(verifier, local)
        return unless verifier.respond_to?(:resource_binding) && verifier.resource_binding
        return if verifier.resource_binding.compatible_with?(local)

        raise Keycardai::OAuth::ConfigurationError,
              "verifier audience policy does not match RequireBearerAuth resource binding"
      end

      def validate_zone_resolver!
        unless @zone_resolver.respond_to?(:call)
          raise Keycardai::OAuth::ConfigurationError,
                "per-zone resource mode requires a request zone_resolver callable without a token"
        end
        return unless token_only_resolver?(@zone_resolver)

        raise Keycardai::OAuth::ConfigurationError,
              "per-zone resource mode requires a resolver that can select a zone without a bearer token"
      end

      def token_only_resolver?(resolver)
        return true if resolver.respond_to?(:token_only?) && resolver.token_only?
        return false unless resolver.respond_to?(:parameters)

        params = resolver.parameters
        params.count { |type, _| type == :req } > 1 || params.include?(%i[keyreq token])
      end
    end
  end
end
