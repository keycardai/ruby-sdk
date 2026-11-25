# frozen_string_literal: true

require "time"

module Keycardai
  module OAuth
    # Gates caller-initiated metadata fetches by cache key.
    class MetadataRetry
      WALL_CLOCK = -> { Time.now }
      MONOTONIC_CLOCK = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      MAX_ENTRIES = 128

      def self.failure_cause(error)
        error.is_a?(JWKSError) ? error.cause : error
      end

      def self.retryable?(error)
        if error.is_a?(NetworkError)
          cause = error.cause
          return !(cause.is_a?(OpenSSL::SSL::SSLError) && cause.message.include?("certificate verify failed"))
        end

        error.is_a?(HTTPError) && (error.status == 429 || (500..599).cover?(error.status))
      end

      def initialize(clock, monotonic_clock: clock.equal?(WALL_CLOCK) ? MONOTONIC_CLOCK : clock)
        @wall_clock = clock
        @monotonic_clock = monotonic_clock
        @states = {}
        @mutex = Mutex.new
        @generation = 0
      end

      def fetch(key)
        started = @mutex.synchronize do
          state = @states[key]
          raise state[:error] if state && @monotonic_clock.call < state[:until]

          @generation
        end

        begin
          value = yield
        rescue Keycardai::Error => e
          @mutex.synchronize { record(key, e) if @generation == started }
          raise
        end
        @mutex.synchronize { @states.delete(key) if @generation == started }
        value
      end

      def delete(key)
        @mutex.synchronize do
          @generation += 1
          @states.delete(key)
        end
      end

      def clear
        @mutex.synchronize do
          @generation += 1
          @states.clear
        end
      end

      private

      def record(key, error)
        cause = self.class.failure_cause(error)
        return unless self.class.retryable?(cause)

        now = @monotonic_clock.call
        next_step = @states.dig(key, :next_step) || 1
        delay = retry_after(cause)
        return if delay.nil? && throttled?(cause)

        if delay.nil?
          delay = [30, next_step * rand(0.8...1.2)].min
          next_step = [64, next_step * 2].min
        end
        remember(key, error: error, until: now + delay, next_step: next_step)
      end

      def remember(key, state)
        @states.delete(key)
        @states[key] = state
        @states.shift if @states.size > MAX_ENTRIES
      end

      def throttled?(error)
        error.is_a?(HTTPError) && error.status == 429
      end

      def retry_after(error)
        return unless error.is_a?(HTTPError) && [429, 503].include?(error.status)

        header = error.retry_after.to_s.strip
        return [60, header.to_i].min if /\A[0-9]+\z/.match?(header)

        wall_now = @wall_clock.call
        date = http_date(header, wall_now)
        (date - wall_now).clamp(0, 60) if date
      rescue ArgumentError
        nil
      end

      def http_date(header, now)
        date = Time.httpdate(header)
        return date if header == date.httpdate || header == date.asctime || header == date.strftime("%a %b %d %T %Y")

        date = adjust_obsolete_year(date, now.getutc)
        date if header == date.strftime("%A, %d-%b-%y %T GMT")
      end

      def adjust_obsolete_year(date, now)
        year = date.year + ((now.year + 50 - date.year).div(100) * 100)
        year -= 100 if year == now.year + 50 && date.strftime("%m%d%T") > now.strftime("%m%d%T")
        Time.utc(year, date.month, date.day, date.hour, date.min, date.sec)
      end
    end
    private_constant :MetadataRetry
  end
end
