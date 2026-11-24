# frozen_string_literal: true

module Keycardai
  module OAuth
    # An HTTP client, with NetHTTPClient's surface, that authorizes every
    # request to one resource with a token from a resource token source (any
    # object answering +resource_token(resource:, scopes:)+, such as
    # AgentTokenSource). The resource is fixed at construction and never
    # derived from the request URL; a caller of several resources builds one
    # transport per resource.
    #
    # Each request asks the source for a token and sets
    # +Authorization: Bearer <token>+ on a copy of the caller's headers,
    # replacing any Authorization header there. An error from the source
    # propagates unwrapped and the request is not sent. No timeout is added:
    # obtaining the token can wait on a human, and the request itself is
    # bounded however +http_client+ bounds it.
    class ResourceTransport
      # @param source [#resource_token] mints the token
      # @param resource [String] the resource indicator every request is
      #   authorized against
      # @param scopes [Array<String>] requested alongside the resource
      # @param http_client [#get, #post_form, #post_json] sends the request
      # @raise [ConfigurationError] a missing source or resource
      def initialize(source: nil, resource: nil, scopes: [], http_client: HTTP::NetHTTPClient.new)
        raise ConfigurationError, "ResourceTransport requires a source" if source.nil?
        raise ConfigurationError, "ResourceTransport requires a resource" if resource.nil? || resource.empty?

        @source = source
        @resource = resource
        @scopes = scopes
        @http_client = http_client
      end

      # @return [HTTP::Response]
      def get(url, headers: {}, timeout: nil)
        @http_client.get(url, headers: authorize(headers), timeout: timeout)
      end

      # @return [HTTP::Response]
      def post_form(url, params, headers: {}, timeout: nil)
        @http_client.post_form(url, params, headers: authorize(headers), timeout: timeout)
      end

      # @return [HTTP::Response]
      def post_json(url, payload, headers: {}, timeout: nil)
        @http_client.post_json(url, payload, headers: authorize(headers), timeout: timeout)
      end

      private

      def authorize(headers)
        token = @source.resource_token(resource: @resource, scopes: @scopes)
        headers.reject { |name, _| name.to_s.casecmp?("authorization") }
               .merge("Authorization" => "Bearer #{token.access_token}")
      end
    end
  end
end
