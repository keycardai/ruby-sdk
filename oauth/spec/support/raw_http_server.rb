# frozen_string_literal: true

require "socket"
require "stringio"
require "zlib"

# A local HTTP/1.1 server for tests that need the real NetHTTPClient, such as
# a body that does not decompress or a request that times out. The block gets
# each request's method and path and returns the raw response bytes, or :hang
# to accept the request and never answer. Connections stay open between
# requests until the client closes them, and +connections+ counts how many
# the server accepted.
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

  # A response that says Content-Encoding: gzip, with a body that is not gzip.
  def self.corrupt_gzip(status)
    response(status, "this is not gzip", "Content-Type" => "application/json", "Content-Encoding" => "gzip")
  end

  # A response with a gzip body that decompresses to +payload+ as JSON.
  def self.gzip_json(status, payload)
    io = StringIO.new
    Zlib::GzipWriter.wrap(io) { |gz| gz.write(JSON.dump(payload)) }
    response(status, io.string, "Content-Type" => "application/json", "Content-Encoding" => "gzip")
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

      socket.write(response)
    end
  rescue IOError, SystemCallError
    nil
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
