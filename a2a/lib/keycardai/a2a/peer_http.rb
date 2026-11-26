# frozen_string_literal: true

module Keycardai
  module A2A
    # Builds the default transport for peer requests.
    module PeerHTTP
      DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024

      def self.client(http_client, limit)
        unless limit.is_a?(Integer) && limit.positive?
          raise ArgumentError, "max_peer_response_bytes must be a positive integer"
        end

        http_client || OAuth::HTTP::NetHTTPClient.new(max_response_bytes: limit)
      end
    end
    private_constant :PeerHTTP
  end
end
