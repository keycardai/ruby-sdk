# frozen_string_literal: true

module Keycardai
  module OAuth
    # Runs at most one fetch per key at a time. A caller that asks for a key
    # while its fetch runs waits and gets the same result, or the same
    # Keycardai::Error. Nothing is kept after the fetch ends, so the next
    # caller fetches again. Callers cache a result themselves.
    #
    # Any other exception ends the fetch for the caller that ran it only. That
    # is how a Timeout.timeout, Thread#raise or Thread#kill aimed at one caller
    # arrives. A waiting caller then runs the fetch itself. Not public API.
    class SingleFlight
      Flight = Struct.new(:state, :value, :error)
      private_constant :Flight

      def initialize
        @mutex = Mutex.new
        @landed = ConditionVariable.new
        @flights = {}
      end

      # @param key [Object] what is fetched; callers with equal keys share one fetch
      # @yieldreturn [Object] the fetched value
      # @return [Object] the value from this caller's fetch or the one it waited on
      # @raise [Keycardai::Error] the fetch failed
      def run(key, &fetch)
        loop do
          flight, owner = @mutex.synchronize do
            existing = @flights[key]
            existing ? [existing, false] : [@flights[key] = Flight.new(:running), true]
          end
          return fly(key, flight, &fetch) if owner

          @mutex.synchronize { @landed.wait(@mutex) while flight.state == :running }
          return flight.value if flight.state == :done
          raise flight.error if flight.state == :failed
        end
      end

      private

      def fly(key, flight)
        state = :abandoned
        value = yield
        state = :done
        flight.value = value
      rescue Keycardai::Error => e
        state = :failed
        flight.error = e
        raise
      ensure
        land(key, flight, state)
      end

      def land(key, flight, state)
        @mutex.synchronize do
          flight.state = state
          @flights.delete(key)
          @landed.broadcast
        end
      end
    end
  end
end
