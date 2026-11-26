# frozen_string_literal: true

module Keycardai
  module OAuth
    # One monotonic budget for a request, independent of wall-clock changes.
    class RequestDeadline
      def initialize(timeout)
        @expires_at = monotonic_time + timeout
      end

      def remaining
        seconds = @expires_at - monotonic_time
        raise NetworkError, "request deadline exceeded" unless seconds.positive?

        seconds
      end

      def credential_options(credential)
        seconds = remaining
        return {} unless credential

        parameters = credential.method(:client_authentication).parameters
        options = {}
        options[:deadline] = Time.now + seconds if accepts_keyword?(parameters, :deadline)
        options[:timeout] = seconds if accepts_keyword?(parameters, :timeout)
        options
      end

      private

      def accepts_keyword?(parameters, keyword)
        parameters.any? { |kind, name| name == keyword && %i[key keyreq].include?(kind) }
      end

      def monotonic_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
    private_constant :RequestDeadline
  end
end
