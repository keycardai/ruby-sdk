# frozen_string_literal: true

require "io/wait"
require "json"
require "socket"
require "uri"

module Keycardai
  module OAuth
    module HTTP
      # Transport over a Unix domain socket, with NetHTTPClient's surface.
      # Net::HTTP dials only TCP, so each request is one HTTP/1.1 exchange on a
      # fresh connection that the client closes after the response. The URL's
      # path and query are sent; its host is a placeholder the peer does not
      # interpret.
      #
      # Unlike NetHTTPClient, a request without a timeout waits without bound:
      # the peer is a local process that may be waiting on a human.
      class UnixSocketClient
        # Bytes of a response body read before the rest is dropped.
        MAX_BODY_BYTES = 1 << 20
        # Longest status or header line accepted.
        MAX_LINE_BYTES = 16 * 1024
        # The same refusal Net::HTTP makes, for the same reason: a CR or LF
        # would let a header value end the header and start another.
        INVALID_HEADER = /[\r\n\0]/

        # @return [String]
        attr_reader :socket_path

        # @param socket_path [String] the Unix socket every request dials
        def initialize(socket_path)
          @socket_path = socket_path
        end

        # @param url [String]
        # @param headers [Hash{String => String}]
        # @param timeout [Numeric, nil] seconds for the whole exchange; nil waits without bound
        # @return [Response]
        # @raise [NetworkError] when the socket cannot be dialled, the
        #   connection fails, or the timeout passes
        def get(url, headers: {}, timeout: nil)
          perform("GET", url, headers, nil, timeout)
        end

        # @param url [String]
        # @param params [Hash] form fields, sent application/x-www-form-urlencoded
        # @param headers [Hash{String => String}]
        # @param timeout [Numeric, nil]
        # @return [Response]
        # @raise [NetworkError]
        def post_form(url, params, headers: {}, timeout: nil)
          headers = { "Content-Type" => "application/x-www-form-urlencoded" }.merge(headers)
          perform("POST", url, headers, URI.encode_www_form(params), timeout)
        end

        # @param url [String]
        # @param payload [Hash] request body, sent as application/json
        # @param headers [Hash{String => String}]
        # @param timeout [Numeric, nil]
        # @return [Response]
        # @raise [NetworkError]
        def post_json(url, payload, headers: {}, timeout: nil)
          headers = { "Content-Type" => "application/json" }.merge(headers)
          perform("POST", url, headers, JSON.dump(payload), timeout)
        end

        private

        def perform(method, url, headers, body, timeout)
          request = request_bytes(method, URI(url), headers, body)
          deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout)
          socket = dial
          begin
            socket.write(request)
            read_response(Reader.new(socket, deadline))
          ensure
            socket.close
          end
        rescue SystemCallError, IOError => e
          raise NetworkError, "request over #{@socket_path} failed: #{e.message}"
        end

        def dial
          UNIXSocket.new(@socket_path)
        rescue ArgumentError => e
          # UNIXSocket raises ArgumentError for a path longer than sun_path.
          raise NetworkError, "cannot dial #{@socket_path}: #{e.message}"
        end

        def request_bytes(method, uri, headers, body)
          lines = ["#{method} #{uri.request_uri} HTTP/1.1", "Host: #{uri.host || "localhost"}"]
          headers.each do |name, value|
            if INVALID_HEADER.match?(name.to_s) || INVALID_HEADER.match?(value.to_s)
              raise ArgumentError, "header #{name.to_s.inspect} contains a line break or NUL"
            end

            lines << "#{name}: #{value}"
          end
          lines << "Content-Length: #{body.bytesize}" if body
          lines << "Connection: close"
          "#{lines.join("\r\n")}\r\n\r\n#{body}"
        end

        def read_response(reader)
          status = reader.line[%r{\AHTTP/1\.[01] (\d{3})}, 1] ||
                   raise(NetworkError, "#{@socket_path} answered with a malformed status line")
          headers = read_headers(reader)
          Response.new(status: status.to_i, headers: headers,
                       body: read_body(reader, headers).force_encoding(Encoding::UTF_8))
        end

        def read_headers(reader)
          headers = Hash.new { |hash, name| hash[name] = [] }
          until (line = reader.line).empty?
            name, value = line.split(":", 2)
            raise NetworkError, "#{@socket_path} answered with a malformed header" if value.nil?

            headers[name.strip.downcase] << value.strip
          end
          headers.default_proc = nil
          headers
        end

        def read_body(reader, headers)
          if headers.fetch("transfer-encoding", []).any? { |coding| coding.downcase.include?("chunked") }
            read_chunked(reader)
          elsif (length = content_length(headers))
            reader.bytes([length, MAX_BODY_BYTES].min)
          else
            reader.rest(MAX_BODY_BYTES)
          end
        rescue ArgumentError
          raise NetworkError, "#{@socket_path} answered with malformed body framing"
        end

        def content_length(headers)
          value = headers["content-length"]&.first
          return nil if value.nil?

          length = Integer(value, 10)
          raise ArgumentError, "negative Content-Length" if length.negative?

          length
        end

        # Stops at the size cap, or at the last chunk without reading trailers:
        # the connection is closed after the response, so nothing after the
        # body needs to be consumed.
        def read_chunked(reader)
          body = String.new(encoding: Encoding::BINARY)
          loop do
            size = Integer(reader.line.split(";", 2).first.strip, 16)
            raise ArgumentError, "negative chunk size" if size.negative?

            take = [size, MAX_BODY_BYTES - body.bytesize].min
            body << reader.bytes(take)
            return body if take < size || size.zero?

            reader.line
          end
        end

        # Buffered reads from the socket, bounded by an optional monotonic
        # deadline that covers the whole response.
        class Reader
          CHUNK_BYTES = 16 * 1024

          def initialize(io, deadline)
            @io = io
            @deadline = deadline
            @buffer = String.new(encoding: Encoding::BINARY)
          end

          # A CRLF-terminated line, without the terminator.
          def line
            until (index = @buffer.index("\r\n"))
              raise NetworkError, "response line exceeds #{MAX_LINE_BYTES} bytes" if @buffer.bytesize > MAX_LINE_BYTES
              raise EOFError, "connection closed before the response completed" unless fill
            end
            @buffer.slice!(0, index + 2).byteslice(0, index)
          end

          def bytes(count)
            while @buffer.bytesize < count
              raise EOFError, "connection closed before the response completed" unless fill
            end
            @buffer.slice!(0, count)
          end

          def rest(limit)
            fill while @buffer.bytesize < limit && !@eof
            @buffer.slice!(0, limit)
          end

          private

          def fill
            return false if @eof

            wait
            @buffer << @io.readpartial(CHUNK_BYTES)
            true
          rescue EOFError
            @eof = true
            false
          end

          def wait
            return unless @deadline

            remaining = @deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            return if remaining.positive? && @io.wait_readable(remaining)

            raise NetworkError, "timed out waiting for the response"
          end
        end
        private_constant :Reader
      end
    end
  end
end
