# frozen_string_literal: true

module Keycardai
  module A2A
    # The target agent's card cannot be fetched, is not valid JSON, or is
    # missing the required name, or its invocation endpoint is refused.
    class DiscoveryError < Keycardai::Error
      def initialize(message = nil, retryable: nil)
        super(message)
        @retryable = retryable
      end

      def retryable?
        @retryable
      end
    end

    # An invocation reply exceeds the decoded peer limit.
    class InvocationResponseBodyTooLargeError < OAuth::ResponseBodyTooLargeError
      def retryable?
        !(200..299).cover?(status) && super
      end
    end

    # The JSON-RPC invocation returned an HTTP error or a JSON-RPC error
    # response. Carries the JSON-RPC error payload when one was returned.
    class InvocationError < Keycardai::Error
      # @return [Hash, nil] the JSON-RPC error object, when present
      attr_reader :rpc_error

      def initialize(message, rpc_error: nil)
        super(message)
        @rpc_error = rpc_error
      end
    end
  end
end
