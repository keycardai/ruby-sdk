# frozen_string_literal: true

require "uri"

module Keycardai
  module A2A
    # The origin policy for endpoints advertised in agent cards.
    class EndpointOrigins
      def initialize(trusted)
        @trusted = trusted.map do |url|
          trusted_origin(url) ||
            raise(OAuth::ConfigurationError, "invalid trusted endpoint origin: expected a bare HTTP or HTTPS origin")
        end.freeze
      end

      def check(endpoint, target)
        endpoint_origin = origin(endpoint)
        target_origin = origin(target)
        unless endpoint_origin && target_origin
          raise DiscoveryError.new("invalid invocation endpoint or target URL for #{target.inspect}", retryable: false)
        end
        return if endpoint_origin == target_origin || @trusted.include?(endpoint_origin)

        raise DiscoveryError.new("endpoint origin #{endpoint_origin} is not trusted for target #{target.inspect}",
                                 retryable: false)
      end

      private

      def trusted_origin(url)
        origin(url) if url.is_a?(String) && url.match?(%r{\Ahttps?://[^\s/?#@\\]+/?\z}i)
      end

      def origin(url)
        uri = URI.parse(url)
        return unless uri.is_a?(URI::HTTP) && uri.host && !uri.host.empty? && (0..65_535).cover?(uri.port)

        "#{uri.scheme.downcase}://#{uri.host.downcase}:#{uri.port}"
      rescue URI::Error
        nil
      end
    end
    private_constant :EndpointOrigins
  end
end
