# frozen_string_literal: true

module Keycardai
  module MCP
    # Rack middleware verifying the Authorization bearer token against the
    # zone's JWKS. Fail-closed: unauthenticated requests are rejected with an
    # RFC 6750 challenge advertising the RFC 9728 resource_metadata URL, and
    # never reach the app. On success the verified AccessToken is stored in
    # the Rack env (Keycardai::MCP.auth_info).
    #
    #   use Keycardai::MCP::RequireBearerAuth,
    #       verifier: Keycardai::OAuth::TokenVerifier.new(issuers: zone_url),
    #       required_scopes: ["mcp:tools"]
    #
    # Route-level gating is this same middleware applied per route with a
    # required_scopes set; every configured scope must be present (all-of), a
    # missing one yielding 403 insufficient_scope.
    class RequireBearerAuth
      # @param app [#call] the downstream Rack app
      # @param verifier [#verify_token] a TokenVerifier
      # @param required_scopes [Array<String>, String, nil] all-of scope set
      # @raise [Keycardai::OAuth::ConfigurationError] nil verifier; an auth
      #   boundary with no verifier is a programming error caught at boot
      def initialize(app, verifier:, required_scopes: nil)
        raise Keycardai::OAuth::ConfigurationError, "RequireBearerAuth requires a verifier" if verifier.nil?

        @app = app
        @verifier = verifier
        @required_scopes = Array(required_scopes)
      end

      def call(env)
        header = env["HTTP_AUTHORIZATION"]
        return RackSupport.challenge_response(env, status: 401) if header.nil? || header.empty?

        parts = header.split
        return [400, { "content-type" => "application/json" }, ['{"error":"invalid_request"}']] if parts.length != 2

        scheme, token = parts
        unless scheme.casecmp("bearer").zero?
          return RackSupport.challenge_response(env, status: 401, error: "invalid_token",
                                                     description: "unsupported authorization scheme")
        end

        authorize(env, token)
      end

      private

      def authorize(env, token)
        access_token, failure = verify(token)
        return RackSupport.challenge_response(env, status: 401, error: "invalid_token", description: failure) if failure

        missing = @required_scopes - access_token.scopes
        unless missing.empty?
          return RackSupport.challenge_response(env, status: 403, error: "insufficient_scope",
                                                     description: "missing required scopes: #{missing.join(" ")}")
        end

        env[ENV_AUTH_INFO] = access_token
        @app.call(env)
      end

      def verify(token)
        [@verifier.verify_token(token), nil]
      rescue Keycardai::Error => e
        [nil, e.message]
      end
    end
  end
end
