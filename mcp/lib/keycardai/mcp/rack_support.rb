# frozen_string_literal: true

require "json"

module Keycardai
  module MCP
    # Shared Rack plumbing: request-origin derivation and the RFC 6750
    # challenge responses. Not public API.
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

      # The RFC 9728 protected-resource metadata URL advertised in challenges.
      def resource_metadata_url(env)
        "#{origin(env)}/.well-known/oauth-protected-resource"
      end

      # An RFC 6750 challenge response. A nil error code produces the bare
      # challenge used for missing credentials.
      def challenge_response(env, status:, error: nil, description: nil)
        params = []
        params << %(error="#{error}") if error
        params << %(error_description="#{description}") if description
        params << %(resource_metadata="#{resource_metadata_url(env)}")
        body = JSON.dump({ "error" => error || "unauthorized" })
        [status,
         { "content-type" => "application/json", "www-authenticate" => "Bearer #{params.join(", ")}" },
         [body]]
      end

      def json_response(payload, status: 200, headers: {})
        [status,
         { "content-type" => "application/json", "access-control-allow-origin" => "*" }.merge(headers),
         [JSON.dump(payload)]]
      end
    end
  end
end
