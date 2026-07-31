# frozen_string_literal: true

module Keycardai
  module OAuth
    # The per-request container of exchanged downstream tokens, keyed by
    # resource, with per-resource error tracking. The grant layer constructs
    # and populates it before the handler runs; handlers read it from the
    # request context. Population is non-throwing by design: failures land on
    # the context so a partial-success flow can proceed when only some
    # exchanges failed.
    #
    # Reading is split between the throwing accessor #access and the
    # non-throwing getters (#resource_error, #error, #errors?, #status, ...),
    # so handlers can inspect state and choose to proceed, degrade, or fail.
    class AccessContext
      # @param tokens [Hash{String => TokenResponse}] seed of successful exchanges
      def initialize(tokens = {})
        @tokens = tokens.dup
        @resource_errors = {}
        @error = nil
        @mutex = Mutex.new
      end

      # The exchanged token for a resource.
      #
      # @param resource [String]
      # @return [TokenResponse]
      # @raise [ResourceAccessError] a global error is set (global_error), the
      #   resource recorded an error (resource_error), or no token exists for
      #   it (missing_token)
      def access(resource)
        @mutex.synchronize do
          raise_access_error("global_error", resource, details: @error) if @error
          if @resource_errors.key?(resource)
            raise_access_error("resource_error", resource, details: @resource_errors[resource])
          end

          @tokens[resource] || raise_access_error("missing_token", resource, available: @tokens.keys)
        end
      end

      # @param resource [String]
      # @return [Object, nil] the recorded error for the resource, nil when it succeeded
      def resource_error(resource)
        @mutex.synchronize { @resource_errors[resource] }
      end

      # @return [Object, nil] the global (context-wide) error
      def error
        @mutex.synchronize { @error }
      end

      # @return [Hash] { resources: Hash{String => Object}, error: Object | nil }
      def errors
        @mutex.synchronize { { resources: @resource_errors.dup, error: @error } }
      end

      # @param resource [String]
      # @return [Boolean]
      def resource_error?(resource)
        @mutex.synchronize { @resource_errors.key?(resource) }
      end

      # @return [Boolean] whether a global error was set
      def error?
        @mutex.synchronize { !@error.nil? }
      end

      # @return [Boolean] whether a global error or any per-resource error exists
      def errors?
        @mutex.synchronize { !@error.nil? || !@resource_errors.empty? }
      end

      # @return ["success", "partial_error", "error"]
      def status
        @mutex.synchronize do
          next "error" unless @error.nil?
          next "partial_error" unless @resource_errors.empty?

          "success"
        end
      end

      # @return [Array<String>] resources holding a successful token
      def successful_resources
        @mutex.synchronize { @tokens.keys }
      end

      # @return [Array<String>] resources with a recorded error
      def failed_resources
        @mutex.synchronize { @resource_errors.keys }
      end

      # Record a successful token, clearing any prior error for the resource.
      # Called by the grant layer, not by handlers.
      #
      # @return [void]
      def set_token(resource, token)
        @mutex.synchronize do
          @resource_errors.delete(resource)
          @tokens[resource] = token
        end
      end

      # Record multiple successful tokens at once.
      #
      # @param tokens [Hash{String => TokenResponse}]
      # @return [void]
      def set_bulk_tokens(tokens)
        @mutex.synchronize do
          tokens.each do |resource, token|
            @resource_errors.delete(resource)
            @tokens[resource] = token
          end
        end
      end

      # Record a per-resource error, clearing any prior token for the resource.
      #
      # @return [void]
      def set_resource_error(resource, error)
        @mutex.synchronize do
          @tokens.delete(resource)
          @resource_errors[resource] = error
        end
      end

      # Record a global (context-wide) error.
      #
      # @return [void]
      def set_error(error)
        @mutex.synchronize { @error = error }
      end

      # Merge another context's tokens and errors into this one.
      #
      # @param other [AccessContext]
      # @return [void]
      def merge(other)
        snapshot = other.errors
        unless snapshot[:error]
          set_bulk_tokens(other.successful_resources.to_h { |resource| [resource, other.access(resource)] })
        end
        snapshot[:resources].each { |resource, error| set_resource_error(resource, error) }
        set_error(snapshot[:error]) if snapshot[:error]
      end

      private

      def raise_access_error(error_type, resource, details: nil, available: [])
        message = {
          "global_error" => "a context-wide error is set",
          "resource_error" => "the exchange for #{resource} failed",
          "missing_token" => "no token was granted for #{resource}"
        }.fetch(error_type)
        raise ResourceAccessError.new(message, resource: resource, error_type: error_type,
                                               error_details: details, available_resources: available)
      end
    end
  end
end
