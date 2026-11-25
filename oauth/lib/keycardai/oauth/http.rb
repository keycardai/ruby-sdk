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
      # +body_error+ is the Zlib error for a gzip or deflate body that
      # arrived whole and is not valid compressed data. The body is then
      # empty. Such a response is malformed. It is not a network error. A
      # body that ends early is a NetworkError, and so is a compressed stream
      # that ends early.
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

      # Streams a Net::HTTP response body up to MAX_RESPONSE_BODY_BYTES
      # decoded bytes, inflating gzip/deflate incrementally so an oversized
      # response stops before buffering or parsing.
      module BoundedBodyReader
        DECOMPRESSED = %w[gzip x-gzip deflate].freeze

        module_function

        def read(response, on_overflow:)
          if DECOMPRESSED.include?(response["content-encoding"]&.downcase)
            read_compressed(response, on_overflow: on_overflow)
          else
            read_plain(response, on_overflow: on_overflow)
          end
        end

        def read_plain(response, on_overflow:)
          decoded = String.new(encoding: Encoding::BINARY)
          each_chunk(response) { |chunk| append(decoded, chunk, response, on_overflow) }
          [decoded, nil]
        end

        def read_compressed(response, on_overflow:)
          decoded = String.new(encoding: Encoding::BINARY)
          state = { saw_bytes: false, raw_bytes: 0, body_error: nil, response: response, on_overflow: on_overflow }
          inflate = Zlib::Inflate.new(32 + Zlib::MAX_WBITS)
          begin
            each_chunk(response) { |chunk| consume_compressed(inflate, chunk, decoded, state) }
            finish_compressed(inflate, decoded, state)
          ensure
            inflate.close
          end
          return ["", state[:body_error]] if state[:body_error]

          strip_encoding_headers(response, decoded)
          [decoded, nil]
        end

        def consume_compressed(inflate, chunk, decoded, state)
          return if chunk.empty?

          state[:saw_bytes] = true
          state[:raw_bytes] += chunk.bytesize
          if state[:body_error]
            check_limit(state[:raw_bytes], state[:response], state[:on_overflow])
            return
          end
          inflate.inflate(chunk) { |out| append(decoded, out, state[:response], state[:on_overflow]) }
        rescue Zlib::DataError => e
          state[:body_error] = e
        end

        def finish_compressed(inflate, decoded, state)
          return unless state[:saw_bytes] && state[:body_error].nil?

          inflate.finish { |out| append(decoded, out, state[:response], state[:on_overflow]) }
        rescue Zlib::DataError => e
          state[:body_error] = e
        end

        def each_chunk(response, &)
          if response.respond_to?(:read_body)
            response.read_body(&)
          else
            yield response.body.to_s
          end
        end

        def strip_encoding_headers(response, decoded)
          response.delete("content-encoding")
          response["content-length"] = decoded.bytesize.to_s if response["content-length"]
        end

        def append(decoded, chunk, response, on_overflow)
          check_limit(decoded.bytesize + chunk.bytesize, response, on_overflow)
          decoded << chunk
        end

        def check_limit(size, response, on_overflow)
          return if size <= MAX_RESPONSE_BODY_BYTES

          on_overflow.call
          raise ResponseBodyTooLargeError.new(status: response.code.to_i)
        end
      end
      private_constant :BoundedBodyReader

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
        # Open, read and write timeout for a request whose caller passed no
        # timeout: 10 seconds, so a request to the zone cannot wait for
        # Net::HTTP's 60. Each one bounds a single step of the request, such as
        # one read from the socket, not the whole request.
        DEFAULT_TIMEOUT = 10

        # What a request raises when the connection or the response fails:
        # DNS, connect, TLS, timeout, a dropped connection, a response
        # Net::HTTP cannot parse, or a body that ends early. Each one becomes
        # a NetworkError. Zlib raises BufError for a gzip stream that ends
        # early, and DataError for a body that is not gzip.
        TRANSPORT_ERRORS = [
          SystemCallError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError, IOError,
          Net::ProtocolError, Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Zlib::BufError
        ].freeze

        # The Accept-Encoding header Net::HTTP sends by default.
        ACCEPT_ENCODING = "gzip;q=1.0,deflate;q=0.6,identity;q=0.3"

        # Content-Encoding values the client decompresses. Zlib reads a gzip
        # or a zlib header for each.
        DECOMPRESSED = %w[gzip x-gzip deflate].freeze

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
        # @param timeout [Numeric, nil] open, read and write timeout in seconds
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
        # @param timeout [Numeric, nil] open, read and write timeout in seconds
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
        # @param timeout [Numeric, nil] open, read and write timeout in seconds
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
          configure_http(http, timeout, request)
          response, body, body_error = execute_request(http, request)
          build_response(response, body, body_error)
        rescue *TRANSPORT_ERRORS => e
          raise NetworkError, "request to #{uri.host} failed: #{e.class}"
        rescue Zlib::Error => e
          build_response(response, "", e)
        end

        def execute_request(http, request)
          yielded = nil
          body = nil
          body_error = nil
          returned = http.request(request) do |res|
            yielded = res
            body, body_error = BoundedBodyReader.read(res, on_overflow: -> { finish(http) })
          end
          return [yielded, body, body_error] if yielded

          body, body_error = BoundedBodyReader.read(returned, on_overflow: -> { finish(http) })
          [returned, body, body_error]
        end

        def configure_http(http, timeout, request)
          http.open_timeout = timeout || DEFAULT_TIMEOUT
          http.read_timeout = timeout || DEFAULT_TIMEOUT
          http.write_timeout = timeout || DEFAULT_TIMEOUT
          http.start unless http.started?
          # Net::HTTP does not report a gzip stream that ends early, so the
          # client decompresses the body itself. Assigning Accept-Encoding
          # turns off Net::HTTP's decompression.
          request["Accept-Encoding"] = ACCEPT_ENCODING if request.decode_content
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
          # Net::HTTP retries a failed GET once by default.
          http.max_retries = 0
          # By default Net::HTTP returns a body shorter than its
          # Content-Length without an error.
          http.ignore_eof = false
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
