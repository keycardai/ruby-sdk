# frozen_string_literal: true

require "json"
require "socket"
require "tmpdir"

# A stub Keycard agent on a real Unix socket. Each connection is one HTTP/1.1
# exchange: the request is parsed and recorded, and the handler's
# [status, payload] answer is sent back (a String payload is sent verbatim, any
# other is JSON-encoded). With chunked: true the body goes out with
# Transfer-Encoding: chunked, as a Go server sends a body it did not buffer.
class FakeAgent
  Request = Struct.new(:verb, :path, :headers, :body, keyword_init: true) do
    def json
      JSON.parse(body)
    end
  end

  attr_reader :path, :requests

  # Serve on +path+ for the duration of the block.
  def self.serve(path, handler = nil, chunked: false)
    agent = new(path, handler, chunked: chunked)
    yield agent
  ensure
    agent&.close
  end

  # A directory short enough for a socket path under it: macOS limits
  # sun_path to 104 bytes, and its default TMPDIR already spends half that.
  def self.short_tmpdir(&)
    Dir.mktmpdir("kc", "/tmp", &)
  end

  def initialize(path, handler = nil, chunked: false)
    @path = path
    @chunked = chunked
    @handler = handler || ->(_request) { [200, { "token" => "agent-token" }] }
    @requests = []
    @server = UNIXServer.new(path)
    @thread = Thread.new { serve_forever }
  end

  def close
    @thread.kill
    @thread.join
    @server.close
  end

  private

  def serve_forever
    loop do
      client = @server.accept
      exchange(client)
    rescue Errno::EPIPE, Errno::ECONNRESET, Errno::ENOTCONN
      # The client stopped reading a long error body and closed.
    ensure
      client&.close
    end
  end

  def exchange(client)
    request = read_request(client)
    @requests << request
    status, payload = @handler.call(request)
    return if status.nil?

    body = payload.is_a?(String) ? payload : JSON.dump(payload)
    client.write(response_bytes(status, body))
  end

  def read_request(client)
    verb, path = client.gets("\r\n").split
    headers = {}
    while (line = client.gets("\r\n").chomp("\r\n")) != ""
      name, value = line.split(":", 2)
      headers[name.downcase] = value.strip
    end
    Request.new(verb: verb, path: path, headers: headers,
                body: client.read(headers.fetch("content-length", "0").to_i))
  end

  def response_bytes(status, body)
    head = "HTTP/1.1 #{status} Status\r\nContent-Type: application/json\r\nConnection: close\r\n"
    return "#{head}Content-Length: #{body.bytesize}\r\n\r\n#{body}" unless @chunked

    half = body.bytesize / 2
    chunks = [body.byteslice(0, half), body.byteslice(half..)].reject(&:empty?)
    "#{head}Transfer-Encoding: chunked\r\n\r\n" \
      "#{chunks.map { |chunk| "#{chunk.bytesize.to_s(16)}\r\n#{chunk}\r\n" }.join}0\r\n\r\n"
  end
end
