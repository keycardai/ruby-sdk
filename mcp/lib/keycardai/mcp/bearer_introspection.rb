# frozen_string_literal: true

require_relative "introspection_metadata"

module Keycardai
  module MCP
    # Checks current token status for a locally verified Rack request.
    class BearerIntrospection
      def initialize(verifier:, credential:, http_client:, timeout:, discovery_ttl:)
        @issuers = credential.respond_to?(:issuers) ? Array(credential.issuers).map { |url| url.chomp("/") } : []
        validate!(verifier, credential)
        @verifier = verifier
        @credential = credential
        @http_client = http_client || Keycardai::OAuth::HTTP::NetHTTPClient.new
        unless @http_client.respond_to?(:get) && @http_client.respond_to?(:post_form)
          raise Keycardai::OAuth::ConfigurationError, "introspection requires an HTTP client with get and post_form"
        end

        @timeout = timeout
        @metadata = IntrospectionMetadata.new(http_client: @http_client, timeout: timeout, ttl: discovery_ttl)
        @reported_errors = {}
        @mutex = Mutex.new
      end

      def verify_inherited_zone(token, zone_id, env)
        return [@verifier.verify_token_for_zone(token, zone_id), nil] if @verifier.respond_to?(:verify_token_for_zone)

        token_info = @verifier.verify_token(token)
        return [token_info, nil] if RackSupport.verified_issuer_for_zone?(env, zone_id, token_info.issuer)

        [nil, "token issuer does not match the selected zone"]
      end

      def authorize(env, access_token, binding, zone_id)
        case check(access_token)
        when :unavailable
          RackSupport.json_response({ "error" => "temporarily_unavailable" }, status: 503)
        when :inactive
          RackSupport.challenge_response(env, status: 401, error: "invalid_token",
                                              description: "token is inactive", binding: binding, zone_id: zone_id)
        else
          env[ENV_ZONE_ID] = zone_id if zone_id
          env[ENV_AUTH_INFO] = access_token
          nil
        end
      end

      private

      def check(access_token)
        token = access_token.token
        issuer = access_token.issuer
        unless @issuers.empty? || @issuers.include?(issuer.chomp("/"))
          raise Keycardai::OAuth::ConfigurationError, "no introspection credential for the verified issuer"
        end

        result = Keycardai::OAuth.introspect_token(
          token: token, credential: @credential, metadata: @metadata.fetch(issuer),
          http_client: @http_client, timeout: @timeout
        )
        result.active ? :active : :inactive
      rescue StandardError => e
        report(e, issuer, token)
        :unavailable
      end

      def validate!(verifier, credential)
        unless credential.respond_to?(:client_authentication)
          raise Keycardai::OAuth::ConfigurationError, "introspection requires a credential with client authentication"
        end

        credential.check_client_authentication if credential.respond_to?(:check_client_authentication)
        return unless @issuers.empty?
        return if verifier.respond_to?(:issuers) && Array(verifier.issuers).uniq.one?

        raise Keycardai::OAuth::ConfigurationError, "an unscoped introspection credential requires one trusted issuer"
      end

      def report(error, issuer, token)
        details = error_details(error)
        message = redact(error.message, token)
        cause = redact(error.cause&.message.to_s, token)
        key = [details, message.hash, cause.hash]
        @mutex.synchronize do
          return if @reported_errors.key?(key)

          @reported_errors[key] = true
          warn "Keycardai::MCP::RequireBearerAuth: introspection failed for #{redact(issuer.to_s, token).dump} " \
               "(#{details.join(", ")}): #{message.dump}"
        end
      end

      def redact(message, token)
        token.to_s.empty? ? message : message.gsub(token, "[REDACTED]")
      end

      def error_details(error)
        details = [error.class.name, error.cause&.class&.name]
        details << "HTTP #{error.status}" if error.is_a?(Keycardai::OAuth::HTTPError)
        if error.is_a?(Keycardai::OAuth::OAuthError) && %w[invalid_client server_error].include?(error.error)
          details << error.error
        end
        details.compact
      end
    end
    private_constant :BearerIntrospection
  end
end
