# frozen_string_literal: true

require "json"

module Keycardai
  # Dynamic client registration (RFC 7591).
  module OAuth
    # The result of registering a client (RFC 7591 §3.2.1). The server's full
    # response, including echoed metadata and AS-specific fields, is preserved
    # in +raw+.
    ClientRegistrationResponse = Data.define(
      :client_id, :client_secret, :client_id_issued_at, :client_secret_expires_at,
      :registration_access_token, :registration_client_uri, :raw
    ) do
      # @param field [String] a response field name
      # @return [Object, nil] the field's value from the full response body
      def [](field)
        raw[field]
      end
    end

    REGISTRATION_METADATA_FIELDS = %w[
      client_name redirect_uris grant_types response_types scope
      token_endpoint_auth_method jwks_uri jwks client_uri logo_uri tos_uri
      policy_uri software_id software_version
    ].freeze

    # Register a new OAuth client with the zone (RFC 7591). Sends only the
    # fields the caller supplies; omitted metadata is defaulted by the
    # authorization server. Vendor-extension fields go in additional_metadata,
    # with named fields winning on conflict.
    #
    # @param issuer [String] the zone's issuer URL; supplies the registration endpoint
    # @param client_name [String, nil]
    # @param redirect_uris [Array<String>, nil] required by RFC 7591 when
    #   grant_types includes authorization_code; enforced by the server
    # @param grant_types [Array<String>, nil]
    # @param response_types [Array<String>, nil]
    # @param scope [String, nil] space-separated scopes
    # @param token_endpoint_auth_method [String, nil]
    # @param jwks_uri [String, nil]
    # @param jwks [Hash, nil]
    # @param client_uri [String, nil]
    # @param logo_uri [String, nil]
    # @param tos_uri [String, nil]
    # @param policy_uri [String, nil]
    # @param software_id [String, nil]
    # @param software_version [String, nil]
    # @param additional_metadata [Hash, nil] vendor or AS-specific fields
    # @param initial_access_token [String, nil] RFC 7591 §3.1 registration
    #   authentication, sent as a Bearer credential
    # @param http_client [#get, #post_json] pluggable transport
    # @param timeout [Numeric, nil]
    # @return [ClientRegistrationResponse]
    # @raise [OAuthError] an RFC 7591 §3.2.2 error (invalid_client_metadata,
    #   invalid_redirect_uri, ...)
    # @raise [HTTPError, ProtocolError, NetworkError]
    def self.register_client(issuer, client_name: nil, redirect_uris: nil, grant_types: nil,
                             response_types: nil, scope: nil, token_endpoint_auth_method: nil,
                             jwks_uri: nil, jwks: nil, client_uri: nil, logo_uri: nil, tos_uri: nil,
                             policy_uri: nil, software_id: nil, software_version: nil,
                             additional_metadata: nil, initial_access_token: nil,
                             http_client: HTTP::NetHTTPClient.new, timeout: nil)
      named = {
        "client_name" => client_name, "redirect_uris" => redirect_uris, "grant_types" => grant_types,
        "response_types" => response_types, "scope" => scope,
        "token_endpoint_auth_method" => token_endpoint_auth_method, "jwks_uri" => jwks_uri,
        "jwks" => jwks, "client_uri" => client_uri, "logo_uri" => logo_uri, "tos_uri" => tos_uri,
        "policy_uri" => policy_uri, "software_id" => software_id, "software_version" => software_version
      }.compact
      body = (additional_metadata || {}).transform_keys(&:to_s).merge(named)

      Registration.post(issuer, body, initial_access_token, http_client, timeout)
    end

    # Internals of dynamic client registration. Not public API.
    module Registration
      module_function

      def post(issuer, body, initial_access_token, http_client, timeout)
        metadata = OAuth.fetch_authorization_server_metadata(issuer, http_client: http_client, timeout: timeout)
        endpoint = metadata.registration_endpoint ||
                   raise(ProtocolError.new("metadata for #{issuer} has no registration_endpoint",
                                           code: "invalid_metadata"))

        headers = { "Accept" => "application/json" }
        headers["Authorization"] = "Bearer #{initial_access_token}" if initial_access_token
        parse(http_client.post_json(endpoint, body, headers: headers, timeout: timeout))
      end

      def parse(response)
        raise TokenRequests.error_for(response) unless response.success?

        build(parse_document(response.body))
      end

      def parse_document(body)
        document = JSON.parse(body)
        unless document.is_a?(Hash) && document["client_id"].is_a?(String) && !document["client_id"].empty?
          raise ProtocolError.new("registration response has no client_id", code: "invalid_response")
        end

        document
      rescue JSON::ParserError
        raise ProtocolError.new("registration response is not valid JSON", code: "invalid_response")
      end

      def build(document)
        ClientRegistrationResponse.new(
          client_id: document["client_id"],
          client_secret: document["client_secret"],
          client_id_issued_at: document["client_id_issued_at"],
          client_secret_expires_at: document["client_secret_expires_at"],
          registration_access_token: document["registration_access_token"],
          registration_client_uri: document["registration_client_uri"],
          raw: document
        )
      end
    end
  end
end
