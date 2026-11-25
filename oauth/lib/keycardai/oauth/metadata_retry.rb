# frozen_string_literal: true

require "time"

module Keycardai
  module OAuth
    # Gates caller-initiated metadata fetches by cache key.
    class MetadataRetry
      def self.failure_cause(error)
        error.is_a?(JWKSError) ? error.cause : error
      end

      def self.retryable?(error)
        return true if error.is_a?(NetworkError)

        error.is_a?(HTTPError) && (error.status == 429 || (500..599).cover?(error.status))
      end

      def initialize(clock)
        @clock = clock
        @states = {}
      end

      def fetch(key)
        state = @states[key]
        raise state[:error] if state && @clock.call < state[:until]

        begin
          value = yield
        rescue Keycardai::Error => e
          record(key, e)
          raise
        end
        @states.delete(key)
        value
      end

      def delete(key) = @states.delete(key)
      def clear = @states.clear

      private

      def record(key, error)
        cause = self.class.failure_cause(error)
        return unless self.class.retryable?(cause)

        now = @clock.call
        next_step = @states.dig(key, :next_step) || 1
        delay = retry_after(now, cause)
        return if delay.nil? && throttled?(cause)

        if delay.nil?
          delay = [30, next_step * rand(0.8...1.2)].min
          next_step = [64, next_step * 2].min
        end
        @states[key] = { error: error, until: now + delay, next_step: next_step }
      end

      def throttled?(error)
        error.is_a?(HTTPError) && error.status == 429
      end

      def retry_after(now, error)
        return unless error.is_a?(HTTPError) && [429, 503].include?(error.status)

        header = error.retry_after.to_s.strip
        return [60, header.to_i].min if /\A[0-9]+\z/.match?(header)

        (Time.httpdate(header) - now).clamp(0, 60)
      rescue ArgumentError
        nil
      end
    end
    private_constant :MetadataRetry
  end
end
