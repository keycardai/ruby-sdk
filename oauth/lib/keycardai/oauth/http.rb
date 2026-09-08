# frozen_string_literal: true

require "json"
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

      # Build an HTTP Basic Authorization header value (RFC 7617).
      #
      # @return [String]
      def self.basic_authorization(client_id, client_secret)
        "Basic #{["#{client_id}:#{client_secret}"].pack("m0")}"
      end

      # Default transport backed by Net::HTTP. TLS is used for https URLs.
      #
      # Sessions are kept open and reused per instance, per thread, per
      # (host, port, scheme). A thread only ever touches its own sessions, so
      # the request path takes no lock; a small mutex guards only the registry
      # of per-thread session maps, and dead threads are swept from it whenever
      # it is touched. There is no transparent retry: a keepalive connection
      # the server dropped while idle surfaces as NetworkError on the next
      # request, the same as any other failure.
      #
      # Call {#close} when no requests are in flight to finish every session.
      # An instance that is never closed, such as the throwaway client built by
      # module-level function defaults, keeps its sessions until it is garbage
      # collected, which closes the underlying sockets.
      class NetHTTPClient
        DEFAULT_OPEN_TIMEOUT = Net::HTTP.new("localhost").open_timeout
        DEFAULT_READ_TIMEOUT = Net::HTTP.new("localhost").read_timeout
        private_constant :DEFAULT_OPEN_TIMEOUT, :DEFAULT_READ_TIMEOUT

        def initialize
          @registry = {}
          @registry_mutex = Mutex.new
        end

        # Finish every open session and clear the registry. The client stays
        # usable; the next request opens fresh sessions. Call only when no
        # requests are in flight on any thread.
        #
        # @return [void]
        def close
          maps = @registry_mutex.synchronize do
            @registry.values.tap { @registry.clear }
          end
          maps.each { |sessions| sessions.each_value { |http| finish(http) } }
        end

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

        # @param url [String]
        # @param params [Hash] form fields, sent application/x-www-form-urlencoded
        # @param headers [Hash{String => String}]
        # @param timeout [Numeric, nil] open/read timeout in seconds
        # @return [Response]
        # @raise [NetworkError] on DNS, TLS, connect, or timeout failures
        def post_form(url, params, headers: {}, timeout: nil)
          uri = URI(url)
          request = Net::HTTP::Post.new(uri)
          headers.each { |name, value| request[name] = value }
          request.set_form_data(params)
          perform(uri, request, timeout)
        end

        # @param url [String]
        # @param payload [Hash] request body, sent as application/json
        # @param headers [Hash{String => String}]
        # @param timeout [Numeric, nil] open/read timeout in seconds
        # @return [Response]
        # @raise [NetworkError] on DNS, TLS, connect, or timeout failures
        def post_json(url, payload, headers: {}, timeout: nil)
          uri = URI(url)
          request = Net::HTTP::Post.new(uri)
          request["Content-Type"] = "application/json"
          headers.each { |name, value| request[name] = value }
          request.body = JSON.dump(payload)
          perform(uri, request, timeout)
        end

        private

        def perform(uri, request, timeout)
          http = session_for(uri)
          # Timeouts are per request; a request without one gets Net::HTTP's
          # defaults back rather than the previous request's values.
          http.open_timeout = timeout || DEFAULT_OPEN_TIMEOUT
          http.read_timeout = timeout || DEFAULT_READ_TIMEOUT
          http.start unless http.started?
          response = http.request(request)
          Response.new(status: response.code.to_i, headers: response.to_hash, body: response.body.to_s)
        rescue SystemCallError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError, EOFError => e
          raise NetworkError, "request to #{uri.host} failed: #{e.class}"
        end

        def session_for(uri)
          sessions = sessions_for_current_thread
          key = [uri.host, uri.port, uri.scheme]
          http = sessions[key]
          return http if http&.started?

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == "https"
          sessions[key] = http
        end

        # A thread's own map is read without the mutex once it exists; the mutex
        # is taken only to register a new thread or to close.
        def sessions_for_current_thread
          @registry[Thread.current] || @registry_mutex.synchronize do
            sweep_dead_threads
            @registry[Thread.current] ||= {}
          end
        end

        # Caller holds @registry_mutex.
        def sweep_dead_threads
          @registry.delete_if do |thread, sessions|
            next false if thread.alive?

            sessions.each_value { |http| finish(http) }
            true
          end
        end

        def finish(http)
          http.finish if http.started?
        rescue IOError
          nil
        end
      end
    end
  end
end
