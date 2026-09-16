# frozen_string_literal: true

module Keycardai
  module MCP
    # Rack app serving the resource server's OAuth discovery surface
    # (RFC 9728 / RFC 8414): the protected-resource metadata (with path
    # insertion for sub-path mounts), a server-side proxy of the zone's
    # authorization-server metadata (returned unmodified), and optionally
    # the server's own public JWKS.
    # Responses carry permissive CORS so browser clients can read them.
    #
    #   run Keycardai::MCP::MetadataApp.new(issuer: zone_url, scopes_supported: ["mcp:tools"])
    class MetadataApp
      PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"
      AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server"
      JWKS_PATH = "/.well-known/jwks.json"

      # @param issuer [String] the zone's issuer URL
      # @param scopes_supported [Array<String>, nil]
      # @param resource_name [String, nil]
      # @param resource_documentation [String, nil]
      # @param public_jwks [Hash, nil] served at /.well-known/jwks.json when set
      # @param http_client [#get] transport for the AS-metadata proxy
      # @param timeout [Numeric] upstream fetch timeout
      def initialize(issuer:, scopes_supported: nil, resource_name: nil, resource_documentation: nil,
                     public_jwks: nil, http_client: Keycardai::OAuth::HTTP::NetHTTPClient.new, timeout: 10)
        raise Keycardai::OAuth::ConfigurationError, "MetadataApp requires an issuer" if issuer.nil? || issuer.empty?

        @issuer = issuer
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
        case path
        when %r{\A#{Regexp.escape(PROTECTED_RESOURCE_PATH)}(/.*)?\z}
          protected_resource_response(env, Regexp.last_match(1).to_s)
        when AUTHORIZATION_SERVER_PATH
          authorization_server_response
        when JWKS_PATH
          jwks_response
        else
          RackSupport.json_response({ "error" => "not_found" }, status: 404)
        end
      end

      private

      def preflight_response
        [204,
         { "access-control-allow-origin" => "*", "access-control-allow-methods" => "GET, OPTIONS",
           "access-control-allow-headers" => "MCP-Protocol-Version" },
         []]
      end

      # RFC 9728, with path insertion: a resource mounted at /mcp is described
      # at /.well-known/oauth-protected-resource/mcp and identified as
      # origin + /mcp.
      def protected_resource_response(env, resource_path)
        origin = RackSupport.origin(env)
        document = {
          "resource" => "#{origin}#{resource_path}",
          "authorization_servers" => [@issuer],
          "bearer_methods_supported" => ["header"],
          "scopes_supported" => @scopes_supported,
          "resource_name" => @resource_name,
          "resource_documentation" => @resource_documentation,
          "jwks_uri" => @public_jwks ? "#{origin}#{JWKS_PATH}" : nil
        }.compact
        RackSupport.json_response(document)
      end

      # RFC 8414 proxy of the zone's metadata, returned unmodified. MCP
      # 2025-06-18 clients send the RFC 8707 resource parameter themselves.
      def authorization_server_response
        metadata = Keycardai::OAuth.fetch_authorization_server_metadata(
          @issuer, http_client: @http_client, timeout: @timeout
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
