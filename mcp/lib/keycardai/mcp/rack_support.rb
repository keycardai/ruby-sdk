# frozen_string_literal: true

require "json"

module Keycardai
  module MCP
    # Shared Rack plumbing: request-origin derivation, request target matching,
    # and RFC 6750 challenge responses. Not public API.
    module RackSupport
      module_function

      # The request origin (scheme + host [+ non-default port]).
      def origin(env)
        scheme = env["rack.url_scheme"] || "http"
        host = env["HTTP_HOST"]
        unless host
          host = env["SERVER_NAME"].to_s
          port = env["SERVER_PORT"].to_s
          default = scheme == "https" ? "443" : "80"
          host = "#{host}:#{port}" unless port.empty? || port == default
        end
        "#{scheme}://#{host}"
      end

      # The public request path (before in-app mount stripping) and query string.
      def request_path_and_query(env)
        ["#{env["SCRIPT_NAME"]}#{env["PATH_INFO"]}", env["QUERY_STRING"].to_s]
      end

      # The RFC 9728 protected-resource metadata URL advertised in challenges.
      def resource_metadata_url(env)
        "#{origin(env)}/.well-known/oauth-protected-resource"
      end

      # Compute the resource_metadata URL for a challenge under the given
      # ResourceBinding, or nil when the mode or request target omits it.
      def challenge_metadata_url(env, binding: nil, zone_id: nil)
        return resource_metadata_url(env) if binding.nil? || binding.legacy?

        identifier = identifier_for_challenge(binding, zone_id)
        return nil unless identifier

        path, query = request_path_and_query(env)
        identifier.matches_request?(path: path, query: query) ? identifier.metadata_url : nil
      end

      def identifier_for_challenge(binding, zone_id)
        if binding.single_resource? || binding.shared_discovery?
          binding.identifier
        elsif binding.per_zone? && zone_id
          binding.zone_identifiers[zone_id]
        end
      end

      # An RFC 6750 challenge response. A nil error code produces the bare
      # challenge used for missing credentials.
      def challenge_response(env, status:, error: nil, description: nil, binding: nil,
                             zone_id: nil, include_metadata: true)
        params = []
        params << %(error="#{error}") if error
        params << %(error_description="#{description}") if description
        metadata_url = include_metadata ? challenge_metadata_url(env, binding: binding, zone_id: zone_id) : nil
        params << %(resource_metadata="#{metadata_url}") if metadata_url
        header = params.empty? ? "Bearer" : "Bearer #{params.join(", ")}"
        body = JSON.dump({ "error" => error || "unauthorized" })
        [status, { "content-type" => "application/json", "www-authenticate" => header }, [body]]
      end

      def json_response(payload, status: 200, headers: {})
        [status,
         { "content-type" => "application/json", "access-control-allow-origin" => "*" }.merge(headers),
         [JSON.dump(payload)]]
      end
    end
  end
end
