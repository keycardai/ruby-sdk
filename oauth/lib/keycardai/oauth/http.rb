# frozen_string_literal: true

require "net/http"
require "uri"

module Keycardai
  module OAuth
    # Pluggable HTTP transport. Every network operation in the SDK goes
    # through an object with this surface, so tests and custom transport
    # policies can inject their own client. No hidden retries: retry policy
    # belongs to the injected client.
    module HTTP
      # A minimal HTTP response: numeric status, header hash, body string.
      Response = Data.define(:status, :headers, :body) do
        # @return [Boolean] whether the status is 2xx
        def success?
          (200..299).cover?(status)
        end
      end

      # Default transport backed by Net::HTTP. TLS is used for https URLs.
      class NetHTTPClient
        # @param url [String]
        # @param headers [Hash{String => String}]
        # @param timeout [Numeric, nil] open/read timeout in seconds
        # @return [Response]
        # @raise [NetworkError] on DNS, TLS, connect, or timeout failures
        def get(url, headers: {}, timeout: nil)
          uri = URI(url)
          request = Net::HTTP::Get.new(uri)
          headers.each { |name, value| request[name] = value }
          perform(uri, request, timeout)
        end

        private

        def perform(uri, request, timeout)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == "https"
          if timeout
            http.open_timeout = timeout
            http.read_timeout = timeout
          end
          response = http.request(request)
          Response.new(status: response.code.to_i, headers: response.to_hash, body: response.body.to_s)
        rescue SystemCallError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError, EOFError => e
          raise NetworkError, "request to #{uri.host} failed: #{e.class}"
        end
      end
    end
  end
end
