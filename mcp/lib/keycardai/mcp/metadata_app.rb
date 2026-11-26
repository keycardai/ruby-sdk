# frozen_string_literal: true

module Keycardai
  module MCP
    # Rack app serving the resource server's OAuth discovery surface
    # (RFC 9728 / RFC 8414): protected-resource metadata, a server-side proxy
    # of the zone's authorization-server metadata (returned unmodified), and
    # optionally the server's own public JWKS.
    # Responses carry permissive CORS so browser clients can read them.
    #
    #   run Keycardai::MCP::MetadataApp.new(
    #     issuer: zone_url,
    #     resource_identifier: "https://api.example.com/mcp",
    #     scopes_supported: ["mcp:tools"]
    #   )
    class MetadataApp
      PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"
      AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server"
      JWKS_PATH = "/.well-known/jwks.json"

      # @return [Keycardai::OAuth::ResourceBinding]
      attr_reader :resource_binding

      # @param issuer [String, nil] the zone's issuer URL, or base issuer URL for zone modes
      # @param resource_identifier [String, nil] exact HTTP(S) URL or URN in single-resource mode
      # @param resource_identifiers_by_zone [Hash{String => String}, nil] zone ID to identifier map
      # @param multi_resource [Boolean] suppress protected-resource route, or opt in to shared discovery with zone map
      # @param allow_any_audience [Boolean] suppress protected-resource route in unrestricted audience mode
      # @param resource_binding [Keycardai::OAuth::ResourceBinding, nil] pre-validated binding (internal composition)
      # @param mount_path [String, nil] mount prefix when mounted under a sub-path
      # @param root_metadata_forwarded [Boolean] set true when a root route or proxy forwards host-root well-known paths
      # @param scopes_supported [Array<String>, nil]
      # @param resource_name [String, nil]
      # @param resource_documentation [String, nil]
      # @param public_jwks [Hash, nil] served at /.well-known/jwks.json when set
      # @param http_client [#get] transport for the AS-metadata proxy
      # @param timeout [Numeric] upstream fetch timeout
      def initialize(issuer: nil, resource_identifier: nil, resource_identifiers_by_zone: nil,
                     multi_resource: false, allow_any_audience: false, resource_binding: nil,
                     mount_path: nil, root_metadata_forwarded: false,
                     scopes_supported: nil, resource_name: nil, resource_documentation: nil,
                     public_jwks: nil, http_client: Keycardai::OAuth::HTTP::NetHTTPClient.new, timeout: 10)
        @resource_binding = resource_binding || resolve_binding(
          issuer, resource_identifier, resource_identifiers_by_zone, multi_resource, allow_any_audience
        )
        validate_issuer!(issuer)
        validate_mount!(mount_path, root_metadata_forwarded)
        @issuer = issuer
        @zone_issuers = build_zone_issuers(issuer)
        @metadata_routes = build_metadata_routes
        @scopes_supported = scopes_supported
        @resource_name = resource_name
        @resource_documentation = resource_documentation
        @public_jwks = public_jwks
        @http_client = http_client
        @timeout = timeout
      end

      def call(env)
        return preflight_response if env["REQUEST_METHOD"] == "OPTIONS"

        path = env["PATH_INFO"].to_s
        query = env["QUERY_STRING"].to_s
        route_request(env, path, query) || RackSupport.json_response({ "error" => "not_found" }, status: 404)
      end

      private

      def resolve_binding(issuer, resource_identifier, zone_map, multi_resource, allow_any)
        Keycardai::OAuth::ResourceBinding.resolve(
          resource_identifier: resource_identifier,
          resource_identifiers_by_zone: zone_map,
          multi_resource: multi_resource,
          allow_any_audience: allow_any,
          accept_audiences: false,
          require_issuer_for_zones: true,
          base_issuer: issuer,
          component: "Keycardai::MCP::MetadataApp"
        )
      end

      def route_request(env, path, query)
        return protected_resource_dispatch(env, path, query) if path.start_with?(PROTECTED_RESOURCE_PATH)
        return authorization_server_dispatch(path) if path.start_with?(AUTHORIZATION_SERVER_PATH)
        return jwks_response if path == JWKS_PATH

        nil
      end

      def validate_issuer!(issuer)
        needs_issuer = @resource_binding.legacy? ||
                       (@resource_binding.single_resource? && @resource_binding.identifier.http?)
        return unless needs_issuer && (issuer.nil? || issuer.empty?)

        raise Keycardai::OAuth::ConfigurationError, "MetadataApp requires an issuer"
      end

      def validate_mount!(mount_path, root_metadata_forwarded)
        return if mount_path.nil? || mount_path.empty? || mount_path == "/"
        return unless @resource_binding.explicit? && @resource_binding.publishes_metadata?
        return if root_metadata_forwarded

        raise Keycardai::OAuth::ConfigurationError,
              "MetadataApp mounted under #{mount_path} requires host-root routing or proxy forwarding " \
              "for /.well-known/oauth-protected-resource"
      end

      def build_zone_issuers(issuer)
        return {}.freeze unless @resource_binding.zone_mode? && issuer && !issuer.empty?

        @resource_binding.zone_issuers(issuer).freeze
      end

      def build_metadata_routes
        return build_single_route if @resource_binding.single_resource? && @resource_binding.identifier.http?
        return build_shared_route if @resource_binding.shared_discovery?
        return build_per_zone_routes if @resource_binding.per_zone?

        {}.freeze
      end

      def build_single_route
        id = @resource_binding.identifier
        { [id.metadata_path, id.query.to_s] => [id, [@issuer]] }.freeze
      end

      def build_shared_route
        id = @resource_binding.identifier
        { [id.metadata_path, id.query.to_s] => [id, @zone_issuers.values] }.freeze
      end

      def build_per_zone_routes
        @resource_binding.zone_identifiers.each_with_object({}) do |(zone_id, id), routes|
          next unless id.http?

          key = [id.metadata_path, id.query.to_s]
          if routes.key?(key)
            raise Keycardai::OAuth::ConfigurationError,
                  "conflicting zones in resource_identifiers_by_zone map to the same metadata URL"
          end

          routes[key] = [id, [@zone_issuers[zone_id]]]
        end.freeze
      end

      def preflight_response
        [204,
         { "access-control-allow-origin" => "*", "access-control-allow-methods" => "GET, OPTIONS",
           "access-control-allow-headers" => "MCP-Protocol-Version" },
         []]
      end

      def protected_resource_dispatch(env, path, query)
        return legacy_protected_resource(env, path) if @resource_binding.legacy?

        entry = @metadata_routes[[path, query]]
        return nil unless entry

        identifier, auth_servers = entry
        render_protected_resource(identifier.raw, auth_servers, identifier.origin)
      end

      def legacy_protected_resource(env, path)
        match = path.match(%r{\A#{Regexp.escape(PROTECTED_RESOURCE_PATH)}(/.*)?\z})
        return nil unless match

        origin = RackSupport.origin(env)
        render_protected_resource("#{origin}#{match[1]}", [@issuer], origin)
      end

      def render_protected_resource(resource, authorization_servers, jwks_origin)
        document = {
          "resource" => resource,
          "authorization_servers" => authorization_servers,
          "bearer_methods_supported" => ["header"],
          "scopes_supported" => @scopes_supported,
          "resource_name" => @resource_name,
          "resource_documentation" => @resource_documentation,
          "jwks_uri" => @public_jwks ? "#{jwks_origin}#{JWKS_PATH}" : nil
        }.compact
        RackSupport.json_response(document)
      end

      def authorization_server_dispatch(path)
        return zone_authorization_server_response(path) if @resource_binding.zone_mode?
        return nil unless path == AUTHORIZATION_SERVER_PATH && @issuer && !@issuer.empty?

        fetch_authorization_server(@issuer)
      end

      def zone_authorization_server_response(path)
        match = path.match(%r{\A#{Regexp.escape(AUTHORIZATION_SERVER_PATH)}/([^/]+)\z})
        return nil unless match

        zone_issuer = @zone_issuers[match[1]]
        return nil unless zone_issuer

        fetch_authorization_server(zone_issuer)
      end

      def fetch_authorization_server(upstream_issuer)
        metadata = Keycardai::OAuth.fetch_authorization_server_metadata(
          upstream_issuer, http_client: @http_client, timeout: @timeout
        )
        RackSupport.json_response(metadata.raw)
      rescue Keycardai::Error
        RackSupport.json_response({ "error" => "bad_gateway" }, status: 502)
      end

      def jwks_response
        return RackSupport.json_response({ "error" => "not_found" }, status: 404) unless @public_jwks

        RackSupport.json_response(@public_jwks)
      end
    end
  end
end
