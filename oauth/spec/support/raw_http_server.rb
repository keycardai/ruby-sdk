# frozen_string_literal: true

require "socket"
require "stringio"
require "zlib"

# A local HTTP/1.1 server for tests that need the real NetHTTPClient, such as
# a body that does not decompress or a request that times out. The block gets
# each request's method and path and returns the raw response bytes, :hang
# to accept the request and never answer, :close to close the connection
# without answering, [bytes, :close] to send the bytes and then close, or
# a callable that writes the response to the socket.
# Connections stay open between requests until the client closes them, and
# +connections+ counts how many the server accepted.
class RawHTTPServer
  attr_reader :connections

  def initialize(&handler)
    @handler = handler
    @server = TCPServer.new("127.0.0.1", 0)
    @connections = 0
    @sockets = []
    @threads = []
    @acceptor = Thread.new { loop { accept(@server.accept) } }
  end

  # @return [String] the URL of +path+ on this server
  def url(path = "/")
    "http://127.0.0.1:#{@server.addr[1]}#{path}"
  end

  def close
    @acceptor.kill
    @threads.each(&:kill)
    @sockets.each { |socket| socket.close unless socket.closed? }
    @server.close
  end

  # A complete response with a JSON body.
  def self.json(status, payload)
    response(status, JSON.dump(payload), "Content-Type" => "application/json")
  end

  def self.trickle_json(payload, delay:, chunks:)
    headers, body = json(200, payload).split("\r\n\r\n", 2)
    lambda do |socket|
      socket.write("#{headers}\r\n\r\n")
      body.bytes.each_slice((body.bytesize.to_f / chunks).ceil) do |bytes|
        sleep(delay)
        socket.write(bytes.pack("C*"))
      end
    end
  end

  # A response that says Content-Encoding: gzip, with a body that is not gzip.
  def self.corrupt_gzip(status)
    response(status, "this is not gzip", "Content-Type" => "application/json", "Content-Encoding" => "gzip")
  end

  # A response with a gzip body that decompresses to +payload+ as JSON.
  def self.gzip_json(status, payload)
    response(status, gzip(JSON.dump(payload)), "Content-Type" => "application/json", "Content-Encoding" => "gzip")
  end

  # A 200 whose body stops halfway. +body+ is :json or :gzip. +framing+ is
  # :length for Content-Length, :chunked for one chunk that stops halfway,
  # or :none for neither.
  def self.cut(body, framing)
    payload = JSON.dump({ "access_token" => "token", "token_type" => "Bearer", "padding" => "x" * 200 })
    payload = gzip(payload) if body == :gzip
    headers = { "Content-Type" => "application/json" }
    headers["Content-Encoding"] = "gzip" if body == :gzip
    headers.merge!(CUT_FRAMING.fetch(framing).call(payload.bytesize))
    half = payload.byteslice(0, payload.bytesize / 2)
    half = "#{payload.bytesize.to_s(16)}\r\n#{half}" if framing == :chunked
    "HTTP/1.1 200 OK\r\n#{headers.map { |name, value| "#{name}: #{value}\r\n" }.join}\r\n#{half}"
  end

  # A 200 whose body arrives whole with Content-Length or chunked encoding,
  # and holds the first half of a gzip stream. +framing+ is :length or
  # :chunked.
  def self.cut_gzip_stream(framing)
    payload = gzip(JSON.dump({ "access_token" => "token", "token_type" => "Bearer", "padding" => "x" * 200 }))
    half = payload.byteslice(0, payload.bytesize / 2)
    headers = { "Content-Type" => "application/json", "Content-Encoding" => "gzip" }
    return response(200, half, headers) if framing == :length

    headers["Transfer-Encoding"] = "chunked"
    "HTTP/1.1 200 OK\r\n#{headers.map { |name, value| "#{name}: #{value}\r\n" }.join}\r\n" \
      "#{half.bytesize.to_s(16)}\r\n#{half}\r\n0\r\n\r\n"
  end

  CUT_FRAMING = {
    length: ->(size) { { "Content-Length" => size.to_s } },
    chunked: ->(_size) { { "Transfer-Encoding" => "chunked" } },
    none: ->(_size) { {} }
  }.freeze

  def self.gzip(data)
    io = StringIO.new
    Zlib::GzipWriter.wrap(io) { |gz| gz.write(data) }
    io.string
  end

  def self.response(status, body, headers = {})
    lines = ["HTTP/1.1 #{status} #{status == 200 ? "OK" : "Status"}"]
    headers.merge("Content-Length" => body.bytesize.to_s).each { |name, value| lines << "#{name}: #{value}" }
    "#{lines.join("\r\n")}\r\n\r\n#{body}"
  end

  private

  def accept(socket)
    @connections += 1
    @sockets << socket
    @threads << Thread.new { serve(socket) }
  end

  # Answer requests on one connection until the client closes it. After
  # :hang, read nothing more.
  def serve(socket)
    while (request = read_request(socket))
      response = @handler.call(*request)
      break if response == :hang
      break socket.close if response == :close
      break socket.write(response.first) && socket.close if response.is_a?(Array)

      send_response(socket, response)
    end
  rescue IOError, SystemCallError
    nil
  end

  def send_response(socket, response)
    response.respond_to?(:call) ? response.call(socket) : socket.write(response)
  end

  # @return [Array(String, String), nil] the method and path, or nil at the
  #   end of the connection
  def read_request(socket)
    request_line = socket.gets or return nil
    length = 0
    while (line = socket.gets) && line != "\r\n"
      name, value = line.split(":", 2)
      length = value.to_i if name.casecmp?("content-length")
    end
    socket.read(length) if length.positive?
    request_line.split.first(2)
  end
end
