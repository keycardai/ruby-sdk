# frozen_string_literal: true

require "English"
require "uri"

module Keycardai
  module MCP
    # Per-middleware discovery cache for verified HTTPS issuers.
    class IntrospectionMetadata
      DEFAULT_TTL = 3600
      Flight = Struct.new(:condition, :done, :metadata, :error)
      private_constant :Flight

      def initialize(http_client:, timeout:, ttl:)
        unless ttl.is_a?(Numeric) && ttl >= 0
          raise Keycardai::OAuth::ConfigurationError, "discovery_ttl must be a nonnegative number"
        end

        @http_client = http_client
        @timeout = timeout
        @ttl = ttl
        @retry = Keycardai::OAuth.const_get(:MetadataRetry, false).new(-> { Time.now }, monotonic_clock: method(:now))
        @entries = {}
        @flights = {}
        @mutex = Mutex.new
      end

      def fetch(issuer)
        validate_https!(issuer, "issuer")
        key = issuer.chomp("/")
        flight = @mutex.synchronize do
          entry = @entries[key]
          return entry.first if entry && now < entry.last
          return wait(@flights[key]) if @flights.key?(key)

          @flights[key] = Flight.new(ConditionVariable.new)
        end
        discover(issuer, key, flight)
      end

      private

      def wait(flight)
        flight.condition.wait(@mutex) until flight.done
        return flight.metadata if flight.metadata

        raise(flight.error || Keycardai::OAuth::NetworkError.new("introspection discovery was interrupted"))
      end

      def discover(issuer, key, flight)
        metadata = @retry.fetch(key) do
          discovered = Keycardai::OAuth.fetch_authorization_server_metadata(
            issuer, http_client: @http_client, timeout: @timeout
          )
          validate_https!(discovered.introspection_endpoint, "introspection_endpoint")
          discovered
        end
      ensure
        finish(key, flight, metadata, $ERROR_INFO)
      end

      def finish(key, flight, metadata, error)
        @mutex.synchronize do
          @entries[key] = [metadata, now + @ttl] if metadata
          @flights.delete(key)
          flight.metadata = metadata
          flight.error = error
          flight.done = true
          flight.condition.broadcast
        end
      end

      def validate_https!(value, name)
        uri = URI.parse(value) if value.is_a?(String)
        return if uri.is_a?(URI::HTTPS) && !uri.host.to_s.empty?

        raise Keycardai::OAuth::ConfigurationError, "#{name} must be an HTTPS URL"
      rescue URI::InvalidURIError
        raise Keycardai::OAuth::ConfigurationError, "#{name} must be an HTTPS URL"
      end

      def now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
    private_constant :IntrospectionMetadata
  end
end
