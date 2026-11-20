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
        # Largest response body accepted; a longer one is refused, not truncated.
        MAX_BODY_BYTES = 1 << 20
        # Longest status or header line accepted.
        MAX_LINE_BYTES = 16 * 1024
        # Header lines, and their total bytes, accepted before the response is
        # refused. Without them a peer could grow the header table forever,
        # since a request without a timeout never gives up on it.
        MAX_HEADER_COUNT = 100
        MAX_HEADER_BYTES = 64 * 1024
        # An RFC 9110 field name. It excludes the leading whitespace of an
        # obs-fold continuation and whitespace before the colon.
        HEADER_NAME = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/
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
        # @param timeout [Numeric, nil] seconds to wait for the response, from
        #   before the dial; nil waits without bound. The dial and the write are
        #   not themselves interrupted.
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
          status = reader.line[%r{\AHTTP/1\.[01] (\d{3})(?: |\z)}, 1] ||
                   raise(NetworkError, "#{@socket_path} answered with a malformed status line")
          headers = read_headers(reader)
          Response.new(status: status.to_i, headers: headers,
                       body: read_body(reader, headers).force_encoding(Encoding::UTF_8))
        end

        def read_headers(reader)
          headers = Hash.new { |hash, name| hash[name] = [] }
          header_lines(reader).each do |line|
            name, value = line.split(":", 2)
            if value.nil? || !HEADER_NAME.match?(name)
              raise NetworkError, "#{@socket_path} answered with a malformed header"
            end

            headers[name.downcase] << value.strip
          end
          headers.default_proc = nil
          headers
        end

        def header_lines(reader)
          lines = []
          bytes = 0
          until (line = reader.line).empty?
            lines << line
            bytes += line.bytesize
            next if lines.size <= MAX_HEADER_COUNT && bytes <= MAX_HEADER_BYTES

            raise NetworkError, "#{@socket_path} answered with more than #{MAX_HEADER_COUNT} headers " \
                                "or #{MAX_HEADER_BYTES} bytes of them"
          end
          lines
        end

        def read_body(reader, headers)
          if (coding = final_transfer_coding(headers))
            raise ArgumentError, "unsupported transfer coding" unless coding == "chunked"

            read_chunked(reader)
          elsif (length = content_length(headers))
            raise body_too_large if length > MAX_BODY_BYTES

            reader.bytes(length)
          else
            reader.rest(MAX_BODY_BYTES + 1).tap { |body| raise body_too_large if body.bytesize > MAX_BODY_BYTES }
          end
        rescue ArgumentError
          raise NetworkError, "#{@socket_path} answered with malformed body framing"
        end

        def body_too_large
          NetworkError.new("#{@socket_path} answered with a body over #{MAX_BODY_BYTES} bytes")
        end

        # RFC 9112 requires chunked to be the final coding whenever one is sent;
        # this client decodes nothing else.
        def final_transfer_coding(headers)
          headers.fetch("transfer-encoding", []).flat_map { |value| value.split(",") }.last&.strip&.downcase
        end

        # Repeated or listed values must agree (RFC 9112 §6.3), and Integer()
        # alone would also accept a sign or underscores.
        def content_length(headers)
          values = headers.fetch("content-length", []).flat_map { |value| value.split(",") }.map(&:strip)
          return nil if values.empty?
          raise ArgumentError, "malformed Content-Length" unless values.uniq.size == 1 && values.first.match?(/\A\d+\z/)

          Integer(values.first, 10)
        end

        # Stops at the last chunk without reading trailers: the connection is
        # closed after the response, so nothing after the body needs consuming.
        def read_chunked(reader)
          body = String.new(encoding: Encoding::BINARY)
          loop do
            size = chunk_size(reader.line)
            return body if size.zero?
            raise body_too_large if body.bytesize + size > MAX_BODY_BYTES

            body << reader.bytes(size)
            raise ArgumentError, "chunk data not followed by CRLF" unless reader.line.empty?
          end
        end

        def chunk_size(line)
          digits = line.split(";", 2).first.strip
          raise ArgumentError, "malformed chunk size" unless digits.match?(/\A\h+\z/)

          Integer(digits, 16)
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
            raise NetworkError, "response line exceeds #{MAX_LINE_BYTES} bytes" if index > MAX_LINE_BYTES

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
