# frozen_string_literal: true

require "json"
require "uri"

module Keycardai
  # Authorization-server discovery (RFC 8414): the operation, its metadata
  # type, and the URL/parsing internals shared with JWKSKeyring.
  module OAuth
    # OAuth 2.0 authorization-server metadata (RFC 8414). Standard fields are
    # first-class members; the complete document, including unknown fields, is
    # preserved in +raw+ and reachable through +[]+.
    AuthorizationServerMetadata = Data.define(
      :issuer, :token_endpoint, :authorization_endpoint, :jwks_uri, :registration_endpoint,
      :grant_types_supported, :token_endpoint_auth_methods_supported, :response_types_supported, :raw
    ) do
      # @param field [String] a metadata field name
      # @return [Object, nil] the field's value from the full document
      def [](field)
        raw[field]
      end
    end

    # Discover OAuth 2.0 authorization-server metadata from an issuer URL
    # (RFC 8414). Performs a single fetch and does not cache; caching belongs
    # to the callers that depend on the endpoints.
    #
    # @param issuer [String] the authorization server's identifier URL
    # @param http_client [#get] pluggable transport
    # @param timeout [Numeric, nil] fetch timeout in seconds
    # @return [AuthorizationServerMetadata]
    # @raise [ConfigurationError] empty or invalid issuer input
    # @raise [HTTPError] non-2xx response
    # @raise [ProtocolError] issuer mismatch (code issuer_mismatch) or a
    #   malformed document (code invalid_metadata)
    # @raise [NetworkError] transport failure
    def self.fetch_authorization_server_metadata(issuer, http_client: HTTP::NetHTTPClient.new, timeout: nil)
      url = Discovery.metadata_url(issuer)
      response = http_client.get(url, headers: { "Accept" => "application/json" }, timeout: timeout)
      unless response.success?
        raise HTTPError.new("discovery for #{issuer} returned HTTP #{response.status}",
                            status: response.status, body: response.body)
      end

      Discovery.parse_metadata(issuer, response.body)
    end

    # Internals of authorization-server discovery, shared with JWKSKeyring.
    module Discovery
      module_function

      # RFC 8414: the well-known path segment is inserted between the host and
      # any issuer path component.
      def metadata_url(issuer)
        raise ConfigurationError, "issuer must be a non-empty URL" if issuer.nil? || issuer.empty?

        uri = URI(issuer)
        raise ConfigurationError, "issuer must be an absolute http(s) URL" unless uri.is_a?(URI::HTTP)

        path = uri.path.chomp("/")
        uri.path = "/.well-known/oauth-authorization-server#{path}"
        uri.to_s
      rescue URI::InvalidURIError
        raise ConfigurationError, "issuer is not a valid URL"
      end

      def parse_metadata(issuer, body)
        document = parse_document(issuer, body)
        validate_issuer(issuer, document)

        AuthorizationServerMetadata.new(
          issuer: document["issuer"],
          token_endpoint: document["token_endpoint"],
          authorization_endpoint: document["authorization_endpoint"],
          jwks_uri: document["jwks_uri"],
          registration_endpoint: document["registration_endpoint"],
          grant_types_supported: document["grant_types_supported"],
          token_endpoint_auth_methods_supported: document["token_endpoint_auth_methods_supported"],
          response_types_supported: document["response_types_supported"],
          raw: document
        )
      end

      def parse_document(issuer, body)
        document = JSON.parse(body)
        unless document.is_a?(Hash)
          raise ProtocolError.new("metadata for #{issuer} is not a JSON object",
                                  code: "invalid_metadata")
        end

        document
      rescue JSON::ParserError
        raise ProtocolError.new("metadata for #{issuer} is not valid JSON", code: "invalid_metadata")
      end

      # RFC 8414 §3.3: the response issuer must be present and match the
      # requested issuer, ignoring a trailing slash.
      def validate_issuer(issuer, document)
        unless document["issuer"].is_a?(String)
          raise ProtocolError.new("metadata for #{issuer} has no issuer", code: "invalid_metadata")
        end
        return if document["issuer"].chomp("/") == issuer.chomp("/")

        raise ProtocolError.new("metadata issuer #{document["issuer"]} does not match requested issuer #{issuer}",
                                code: "issuer_mismatch")
      end
    end
  end
end
