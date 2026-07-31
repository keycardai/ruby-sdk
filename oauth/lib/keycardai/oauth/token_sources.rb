# frozen_string_literal: true

require "json"
require "socket"
require "uri"

module Keycardai
  module OAuth
    # Reads a platform-projected identity token file, fresh on every call.
    # Covers EKS (AWS_* env vars), AKS (AZURE_FEDERATED_TOKEN_FILE), any
    # Kubernetes projected service-account token, and file-mode CI providers.
    #
    # Path discovery through the well-known env vars below is the one blessed
    # environment read in the SDK (a deliberate platform convention). An
    # explicit token_file_path wins; env_var_name is consulted first when
    # given. The resolved file is validated at construction (exists,
    # non-empty), preserving fail-fast behavior.
    class FileTokenSource
      DEFAULT_ENV_VARS = %w[
        KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE
        AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
        AWS_WEB_IDENTITY_TOKEN_FILE
        AZURE_FEDERATED_TOKEN_FILE
      ].freeze

      # @param token_file_path [String, nil] explicit path; skips discovery
      # @param env_var_name [String, nil] extra env var consulted first
      # @param env [Hash] the environment to discover from; override in tests
      # @raise [WorkloadIdentityConfigurationError] no path resolved, or the
      #   resolved file is missing or empty
      def initialize(token_file_path: nil, env_var_name: nil, env: ENV)
        @path = token_file_path || discover_path(env_var_name, env)
        validate_file
      end

      # @return [String] the current platform token, read fresh
      # @raise [WorkloadIdentityRuntimeError] unreadable or empty file
      def identity_token
        token = File.read(@path).strip
        raise WorkloadIdentityRuntimeError.new("token file #{@path} is empty", source: "file") if token.empty?

        token
      rescue SystemCallError => e
        raise WorkloadIdentityRuntimeError.new("token file #{@path} is unreadable: #{e.message}", source: "file")
      end

      def source_identifier
        "file"
      end

      private

      def discover_path(env_var_name, env)
        [env_var_name, *DEFAULT_ENV_VARS].compact.each do |name|
          value = env[name]
          return value if value && !value.empty?
        end
        raise WorkloadIdentityConfigurationError.new(
          "no token_file_path given and no discovery env var set (#{DEFAULT_ENV_VARS.join(", ")})",
          source: "file"
        )
      end

      def validate_file
        return if File.file?(@path) && !File.empty?(@path)

        raise WorkloadIdentityConfigurationError.new("token file #{@path} is missing or empty", source: "file")
      end
    end

    # Fetches an identity token from the GCP metadata server. Covers GKE,
    # GCE, and Cloud Run.
    class GCPMetadataTokenSource
      DEFAULT_METADATA_URL = "http://metadata.google.internal"
      IDENTITY_PATH = "/computeMetadata/v1/instance/service-accounts/default/identity"

      # @param audience [String] the aud claim the platform mints into the token
      # @param metadata_url [String] override for testing
      # @param timeout [Numeric, nil]
      # @param http_client [#get] pluggable transport
      # @raise [WorkloadIdentityConfigurationError] missing audience
      def initialize(audience:, metadata_url: DEFAULT_METADATA_URL, timeout: nil,
                     http_client: HTTP::NetHTTPClient.new)
        if audience.nil? || audience.empty?
          raise WorkloadIdentityConfigurationError.new("GCPMetadataTokenSource requires an audience",
                                                       source: "gcp-metadata")
        end

        @audience = audience
        @metadata_url = metadata_url
        @timeout = timeout
        @http_client = http_client
      end

      # @return [String] the current platform token
      # @raise [WorkloadIdentityRuntimeError] endpoint unreachable or non-200
      def identity_token
        url = "#{@metadata_url}#{IDENTITY_PATH}?#{URI.encode_www_form("audience" => @audience, "format" => "full")}"
        response = begin
          @http_client.get(url, headers: { "Metadata-Flavor" => "Google" }, timeout: @timeout)
        rescue NetworkError => e
          raise WorkloadIdentityRuntimeError.new("metadata server unreachable: #{e.message}", source: "gcp-metadata")
        end
        unless response.success?
          raise WorkloadIdentityRuntimeError.new("metadata server returned HTTP #{response.status}",
                                                 source: "gcp-metadata")
        end

        response.body
      end

      def source_identifier
        "gcp-metadata"
      end
    end

    # Fetches an identity token from the Fly.io machines API over its local
    # Unix socket.
    class FlyTokenSource
      DEFAULT_SOCKET_PATH = "/.fly/api"
      TOKEN_PATH = "/v1/tokens/oidc"

      # @param audience [String, nil] included as {"aud": audience} when set
      # @param socket_path [String]
      def initialize(audience: nil, socket_path: DEFAULT_SOCKET_PATH)
        @audience = audience
        @socket_path = socket_path
      end

      # @return [String] the current platform token
      # @raise [WorkloadIdentityRuntimeError] socket unreachable or non-200
      def identity_token
        body = JSON.dump(@audience ? { "aud" => @audience } : {})
        status, response_body = post_over_socket(body)
        unless (200..299).cover?(status)
          raise WorkloadIdentityRuntimeError.new("fly API returned HTTP #{status}", source: "fly")
        end

        response_body
      end

      def source_identifier
        "fly"
      end

      private

      def post_over_socket(body)
        UNIXSocket.open(@socket_path) do |socket|
          socket.write("POST #{TOKEN_PATH} HTTP/1.1\r\n" \
                       "Host: localhost\r\n" \
                       "Content-Type: application/json\r\n" \
                       "Content-Length: #{body.bytesize}\r\n" \
                       "Connection: close\r\n\r\n#{body}")
          parse_http_response(socket.read)
        end
      rescue SystemCallError => e
        raise WorkloadIdentityRuntimeError.new("fly API socket #{@socket_path} unreachable: #{e.message}",
                                               source: "fly")
      end

      def parse_http_response(raw)
        header, body = raw.split("\r\n\r\n", 2)
        status = header[%r{\AHTTP/\d\.\d (\d{3})}, 1].to_i
        [status, body.to_s]
      end
    end
  end
end
