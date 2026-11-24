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
      # the peer is a local process that may be waiting on a human. A timeout
      # bounds the whole exchange, the dial and the write included.
      class UnixSocketClient
        # Largest 2xx response body accepted; a longer one is refused, not
        # truncated.
        MAX_BODY_BYTES = 1 << 20
        # Bytes of any other response's body returned. Reading stops there and
        # the rest is never read, so a long error body still comes back as a
        # Response carrying its status.
        MAX_ERROR_BODY_BYTES = 64 * 1024
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

        # A 2xx response whose body is over MAX_BODY_BYTES. Separate from other
        # NetworkErrors because the peer did answer, and a caller may classify
        # that as a bad response rather than a failed connection.
        class BodyTooLargeError < NetworkError; end

        # @return [String]
        attr_reader :socket_path

        # @param socket_path [String] the Unix socket every request dials
        def initialize(socket_path)
          @socket_path = socket_path
        end

        # @param url [String]
        # @param headers [Hash{String => String}]
        # @param timeout [Numeric, nil] seconds the whole exchange may take: the
        #   dial, writing the request, and reading the response. nil waits
        #   without bound.
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
          deadline = timeout && Deadline.after(timeout)
          socket = dial(deadline)
          begin
            deadline ? deadline.write(socket, request) : socket.write(request)
            read_response(Reader.new(socket, deadline))
          ensure
            socket.close
          end
        rescue SystemCallError, IOError => e
          raise NetworkError, "request over #{@socket_path} failed: #{e.message}"
        end

        def dial(deadline)
          deadline ? deadline.dial(@socket_path) : UNIXSocket.new(@socket_path)
        rescue ArgumentError => e
          # Both raise ArgumentError for a path longer than sun_path.
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
          status = status.to_i
          headers = read_headers(reader)
          body = (200..299).cover?(status) ? read_body(reader, headers) : read_error_body(reader, headers)
          Response.new(status: status, headers: headers, body: body.force_encoding(Encoding::UTF_8))
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
          length = content_length(headers) unless final_transfer_coding(headers)
          raise body_too_large if length && length > MAX_BODY_BYTES

          body = read_framed(reader, headers, MAX_BODY_BYTES + 1)
          raise body_too_large if body.bytesize > MAX_BODY_BYTES

          body
        rescue ArgumentError
          raise malformed_framing
        end

        def read_error_body(reader, headers)
          read_framed(reader, headers, MAX_ERROR_BODY_BYTES)
        rescue ArgumentError
          raise malformed_framing
        end

        # The body, or its first +limit+ bytes when it is longer.
        def read_framed(reader, headers, limit)
          if (coding = final_transfer_coding(headers))
            raise ArgumentError, "unsupported transfer coding" unless coding == "chunked"

            read_chunked(reader, limit)
          elsif (length = content_length(headers))
            reader.bytes([length, limit].min)
          else
            reader.rest(limit)
          end
        end

        def malformed_framing
          NetworkError.new("#{@socket_path} answered with malformed body framing")
        end

        def body_too_large
          BodyTooLargeError.new("#{@socket_path} answered with a body over #{MAX_BODY_BYTES} bytes")
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

        # Stops at the last chunk, or once +limit+ bytes are read, without
        # reading trailers: the connection is closed after the response, so
        # nothing after what is returned needs consuming.
        def read_chunked(reader, limit)
          body = String.new(encoding: Encoding::BINARY)
          loop do
            size = chunk_size(reader.line)
            return body if size.zero?
            return body << reader.bytes(limit - body.bytesize) if body.bytesize + size >= limit

            body << reader.bytes(size)
            raise ArgumentError, "chunk data not followed by CRLF" unless reader.line.empty?
          end
        end

        def chunk_size(line)
          digits = line.split(";", 2).first.strip
          raise ArgumentError, "malformed chunk size" unless digits.match?(/\A\h+\z/)

          Integer(digits, 16)
        end

        # A monotonic deadline for one exchange, and the dial and write that
        # it bounds.
        class Deadline
          def self.after(seconds)
            new(Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds)
          end

          def initialize(at)
            @at = at
          end

          def dial(path)
            address = Socket.sockaddr_un(path)
            socket = Socket.new(:UNIX, :STREAM)
            connect(socket, address)
            socket
          rescue StandardError
            socket&.close
            raise
          end

          def write(socket, bytes)
            until bytes.empty?
              written = socket.write_nonblock(bytes, exception: false)
              if written == :wait_writable
                wait(socket, :wait_writable, "sending the request")
              else
                bytes = bytes.byteslice(written..)
              end
            end
          end

          # Waits for +io+ to become readable or writable (+direction+ is
          # :wait_readable or :wait_writable), and raises once the deadline
          # passes.
          def wait(io, direction, doing)
            return if io.public_send(direction, remaining(doing))

            raise NetworkError, "timed out #{doing}"
          end

          private

          # A Unix connect waits for room in the peer's listen backlog, not for
          # an accept. Linux reports a full backlog to a non-blocking connect as
          # EAGAIN, and polling an unconnected socket says nothing of when room
          # frees up, so the connect is retried with backoff until the deadline.
          # macOS refuses the connect outright.
          def connect(socket, address)
            backoff = 0.001
            begin
              socket.connect_nonblock(address)
            rescue Errno::EAGAIN
              sleep([backoff, remaining("connecting")].min)
              backoff = [backoff * 2, 0.05].min
              retry
            rescue IO::WaitWritable
              wait(socket, :wait_writable, "connecting")
              retry
            rescue Errno::EISCONN
              # The retry after an in-progress connect completed.
            end
          end

          def remaining(doing)
            remaining = @at - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            remaining.positive? ? remaining : raise(NetworkError, "timed out #{doing}")
          end
        end
        private_constant :Deadline

        # Buffered reads from the socket, bounded by an optional Deadline that
        # covers the whole exchange.
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
            @deadline&.wait(@io, :wait_readable, "waiting for the response")
          end
        end
        private_constant :Reader
      end
    end
  end
end
