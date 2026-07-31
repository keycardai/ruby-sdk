# frozen_string_literal: true

require "uri"

module Keycardai
  module MCP
    # Rack app serving the resource server's OAuth discovery surface
    # (RFC 9728 / RFC 8414): the protected-resource metadata (with path
    # insertion for sub-path mounts), a server-side proxy of the zone's
    # authorization-server metadata (with the resource= rewrite shim for
    # pre-RFC-8707 MCP clients), and optionally the server's own public JWKS.
    # Responses carry permissive CORS so browser clients can read them.
    #
    #   run Keycardai::MCP::MetadataApp.new(issuer: zone_url, scopes_supported: ["mcp:tools"])
    class MetadataApp
      PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"
      AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server"
      JWKS_PATH = "/.well-known/jwks.json"
      LEGACY_MCP_PROTOCOL_VERSION = "2025-03-26"

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
          authorization_server_response(env)
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
        legacy = env["HTTP_MCP_PROTOCOL_VERSION"] == LEGACY_MCP_PROTOCOL_VERSION
        document = {
          "resource" => "#{origin}#{resource_path}",
          "authorization_servers" => [legacy ? origin : @issuer],
          "bearer_methods_supported" => ["header"],
          "scopes_supported" => @scopes_supported,
          "resource_name" => @resource_name,
          "resource_documentation" => @resource_documentation,
          "jwks_uri" => @public_jwks ? "#{origin}#{JWKS_PATH}" : nil
        }.compact
        RackSupport.json_response(document)
      end

      # RFC 8414 proxy of the zone's metadata, rewriting the
      # authorization_endpoint to carry resource=<origin> (replacing any
      # resource parameter already present in the upstream value).
      def authorization_server_response(env)
        metadata = Keycardai::OAuth.fetch_authorization_server_metadata(
          @issuer, http_client: @http_client, timeout: @timeout
        )
        document = metadata.raw.dup
        if document["authorization_endpoint"]
          document["authorization_endpoint"] =
            with_resource_param(document["authorization_endpoint"], RackSupport.origin(env))
        end
        RackSupport.json_response(document)
      rescue Keycardai::Error
        RackSupport.json_response({ "error" => "bad_gateway" }, status: 502)
      end

      def with_resource_param(endpoint, resource)
        uri = URI(endpoint)
        params = URI.decode_www_form(uri.query.to_s)
        params.delete_if { |pair| pair.first == "resource" }
        params << ["resource", resource]
        uri.query = URI.encode_www_form(params)
        uri.to_s
      end

      def jwks_response
        return RackSupport.json_response({ "error" => "not_found" }, status: 404) unless @public_jwks

        RackSupport.json_response(@public_jwks)
      end
    end
  end
end
