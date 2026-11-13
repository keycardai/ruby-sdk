# frozen_string_literal: true

require "json"
require "net/http"
require "uri"
require "zlib"

module Keycardai
  module OAuth
    # Pluggable HTTP transport. Every network operation in the SDK goes
    # through an object with this surface, so tests and custom transport
    # policies can inject their own client. An injected client returns
    # HTTP::Response. No hidden retries: retry policy belongs to the injected
    # client.
    module HTTP
      # A minimal HTTP response: numeric status, header hash, body string.
      #
      # +body_error+ is the Zlib error raised when a body with a
      # Content-Encoding such as gzip does not decompress. The body is then
      # empty. Such a response is malformed. It is not a network error.
      # Net::HTTP does not raise for a truncated gzip body; the body is then
      # what it decompressed, and +body_error+ is nil.
      Response = Data.define(:status, :headers, :body, :body_error) do
        # @param status [Integer]
        # @param headers [Hash{String => Array<String>}]
        # @param body [String]
        # @param body_error [Exception, nil]
        def initialize(status:, headers:, body:, body_error: nil)
          super
        end

        # @return [Boolean] whether the status is 2xx
        def success?
          (200..299).cover?(status)
        end
      end

      # Build an HTTP Basic Authorization header value (RFC 7617) for client
      # authentication. RFC 6749 §2.3.1 requires each value to be
      # percent-encoded before it is joined with ":" and base64-encoded.
      #
      # @param client_id [String]
      # @param client_secret [String]
      # @return [String]
      def self.basic_authorization(client_id, client_secret)
        "Basic #{["#{percent_encode(client_id)}:#{percent_encode(client_secret)}"].pack("m0")}"
      end

      # Percent-encode every byte of the UTF-8 value except ASCII letters,
      # digits, and "-._~". A space becomes %20, not "+". The result decodes
      # to the value with both a form decoder (RFC 6749 Appendix B) and a
      # percent decoder. A binary (ASCII-8BIT) string is encoded byte for
      # byte; a string in another encoding is converted to UTF-8 first.
      #
      # @param value [String]
      # @return [String]
      def self.percent_encode(value)
        value = value.to_s
        value = value.encode(Encoding::UTF_8) unless value.encoding == Encoding::BINARY
        value.b.gsub(/[^A-Za-z0-9\-._~]/n) { |byte| format("%%%02X", byte.ord) }
      end
      private_class_method :percent_encode

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
        # Open and read timeout for a request whose caller passed no timeout:
        # 10 seconds, so a request to the zone cannot wait for Net::HTTP's 60.
        DEFAULT_TIMEOUT = 10

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
          # Timeouts are per request; a request without one gets the default
          # back rather than the previous request's values.
          http.open_timeout = timeout || DEFAULT_TIMEOUT
          http.read_timeout = timeout || DEFAULT_TIMEOUT
          http.start unless http.started?
          # Net::HTTP reads the body after the block returns, so +received+
          # holds the status when the body does not decompress.
          received = nil
          response = http.request(request) { |res| received = res }
          build_response(response, response.body.to_s)
        rescue Zlib::Error => e
          build_response(received, "", e)
        rescue SystemCallError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError, EOFError => e
          raise NetworkError, "request to #{uri.host} failed: #{e.class}"
        end

        def build_response(response, body, body_error = nil)
          Response.new(status: response.code.to_i, headers: response.to_hash, body: body, body_error: body_error)
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
