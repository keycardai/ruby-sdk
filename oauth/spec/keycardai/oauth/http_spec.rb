# frozen_string_literal: true

# NetHTTPClient session reuse, stubbed at the Net::HTTP seam. The shared
# FakeHTTPClient replaces the transport entirely and cannot observe sessions,
# so these specs fake Net::HTTP.new itself. No network.
RSpec.describe Keycardai::OAuth::HTTP::NetHTTPClient do
  # A plain 200 with a JSON body. +[]+ reads a header, as on Net::HTTPResponse.
  fake_response = Struct.new(:code, :to_hash, :body) do
    def [](name)
      to_hash[name]&.first
    end
  end

  # Stands in for a Net::HTTP session: tracks started state, timeouts, and
  # the requests it served.
  fake_session = Class.new do
    attr_reader :host, :port, :requests
    attr_accessor :use_ssl, :open_timeout, :read_timeout, :write_timeout, :max_retries, :ignore_eof, :fail_with

    def initialize(host, port, response_class)
      @response_class = response_class
      @host = host
      @port = port
      @started = false
      @requests = []
      @open_timeout = 60
      @read_timeout = 60
      @write_timeout = 60
    end

    def start
      @started = true
    end

    def started?
      @started
    end

    def finish
      @started = false
    end

    def request(req)
      raise fail_with if fail_with

      @requests << req
      @response_class.new("200", { "content-type" => ["application/json"] }, "{}")
    end
  end

  let(:sessions) { [] }
  let(:client) { described_class.new }

  before do
    allow(Net::HTTP).to receive(:new) do |host, port|
      fake_session.new(host, port, fake_response).tap { |s| sessions << s }
    end
  end

  it "reuses one session for two same-thread requests to one host" do
    client.get("https://zone.example/a")
    client.post_form("https://zone.example/token", { "grant_type" => "x" })

    expect(sessions.size).to eq(1)
    expect(sessions.first.requests.size).to eq(2)
    expect(sessions.first).to be_started
  end

  it "keys sessions by host, port, and scheme" do
    client.get("https://zone.example/a")
    client.get("https://other.example/a")
    client.get("http://zone.example/a")

    expect(sessions.size).to eq(3)
    expect(sessions.map(&:use_ssl)).to eq([true, true, false])
    expect(sessions.map(&:port)).to eq([443, 443, 80])
  end

  it "gives each thread its own session" do
    client.get("https://zone.example/a")
    Thread.new { client.get("https://zone.example/a") }.join

    expect(sessions.size).to eq(2)
    expect(sessions.map { |s| s.requests.size }).to eq([1, 1])
  end

  it "applies the timeout per request and restores the 10 second default when absent" do
    client.get("https://zone.example/a", timeout: 2.5)
    session = sessions.first
    expect([session.open_timeout, session.read_timeout, session.write_timeout]).to all(be_between(0, 2.5))

    client.get("https://zone.example/b")
    expect([session.open_timeout, session.read_timeout, session.write_timeout]).to all(be_between(9, 10))
  end

  it "a request with no timeout never inherits Net::HTTP's 60 second default" do
    client.get("https://zone.example/a")
    session = sessions.first
    expect([session.open_timeout, session.read_timeout, session.write_timeout]).to all(be_between(9, 10))
  end

  it "close finishes sessions and the next request opens a fresh one" do
    client.get("https://zone.example/a")
    first = sessions.first

    client.close
    expect(first).not_to be_started

    client.get("https://zone.example/a")
    expect(sessions.size).to eq(2)
    expect(sessions.last).not_to equal(first)
    expect(sessions.last).to be_started
  end

  it "sweeps a dead thread's sessions from the registry" do
    Thread.new { client.get("https://zone.example/a") }.join
    dead_session = sessions.first
    expect(dead_session).to be_started

    client.get("https://zone.example/a")

    registry = client.instance_variable_get(:@registry)
    expect(registry.keys).to eq([Thread.current])
    expect(dead_session).not_to be_started
  end

  [
    EOFError.new("end of file reached"),
    IOError.new("closed stream"),
    Errno::ECONNREFUSED.new,
    Net::OpenTimeout.new,
    Net::ReadTimeout.new,
    OpenSSL::SSL::SSLError.new("certificate verify failed"),
    Net::HTTPBadResponse.new("wrong status line"),
    Net::HTTPHeaderSyntaxError.new("wrong header line format"),
    Zlib::BufError.new("buffer error")
  ].each do |error|
    it "raises #{error.class} from the transport as a NetworkError that names the class" do
      client.get("https://zone.example/a")
      sessions.first.fail_with = error

      expect { client.get("https://zone.example/a") }
        .to raise_error(Keycardai::OAuth::NetworkError, "request to zone.example failed: #{error.class}")
    end
  end

  it "turns off Net::HTTP's retry of a failed GET and its acceptance of a short body" do
    client.get("https://zone.example/a")

    expect(sessions.first).to have_attributes(max_retries: 0, ignore_eof: false)
  end
end

RSpec.describe Keycardai::OAuth::HTTP::NetHTTPClient, "proxy selection" do
  it "does not open a connection when the proxy lookup exhausts the request budget" do
    stub_const("ENV", { "http_proxy" => "http://127.0.0.1:3128" })
    elapsed = 0.0
    allow(Process).to receive(:clock_gettime).and_call_original
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { elapsed }
    expect(IPSocket).to receive(:getaddress).with("zone.example") do
      elapsed = 0.25
      "192.0.2.1"
    end
    expect(TCPSocket).not_to receive(:open)

    expect { described_class.new.get("http://zone.example/a", timeout: 0.2) }
      .to raise_error(Keycardai::OAuth::NetworkError, "request deadline exceeded")
  end
end

# These tests use the real Net::HTTP, which decompresses a gzip body while it
# reads it.
RSpec.describe Keycardai::OAuth::HTTP::NetHTTPClient, "response bodies" do
  let(:client) { described_class.new }

  after { @server&.close }

  def serve(*responses)
    queue = responses.dup
    @server = RawHTTPServer.new { queue.shift }
  end

  # The second request is a POST, which Net::HTTP does not retry, so it
  # succeeds only if the client does not reuse a broken connection. The
  # client reads the whole body before it decompresses it, so one connection
  # serves both requests.
  [
    { name: "a 200 with a gzip body that does not decompress", response: RawHTTPServer.corrupt_gzip(200),
      status: 200, body: "", body_error: Zlib::DataError },
    { name: "a 503 with a gzip body that does not decompress", response: RawHTTPServer.corrupt_gzip(503),
      status: 503, body: "", body_error: Zlib::DataError },
    { name: "a 200 with a gzip body", response: RawHTTPServer.gzip_json(200, { "ok" => true }),
      status: 200, body: '{"ok":true}', body_error: NilClass },
    { name: "a 200 with a deflate body",
      response: RawHTTPServer.response(200, Zlib::Deflate.deflate('{"ok":true}'), "Content-Encoding" => "deflate"),
      status: 200, body: '{"ok":true}', body_error: NilClass }
  ].each do |example|
    it "returns #{example[:name]} with its status, and the next POST on the client succeeds" do
      serve(example[:response], RawHTTPServer.json(200, { "next" => true }))

      response = client.post_form(@server.url("/token"), { "grant_type" => "x" })
      following = client.post_form(@server.url("/next"), { "grant_type" => "x" })

      expect(response).to have_attributes(status: example[:status], body: example[:body])
      expect(response.body_error).to be_an_instance_of(example[:body_error])
      expect(following).to have_attributes(status: 200, body: '{"next":true}')
      expect(@server.connections).to eq(1)
    end
  end

  [
    { name: "a GET", call: ->(client, url) { client.get(url) } },
    { name: "a POST", call: ->(client, url) { client.post_form(url, { "grant_type" => "x" }) } }
  ].each do |example|
    it "sends #{example[:name]} once when the server closes the connection without answering" do
      requests = Queue.new
      @server = RawHTTPServer.new do |method, _path|
        requests << method
        :close
      end

      expect { example[:call].call(client, @server.url("/a")) }
        .to raise_error(Keycardai::OAuth::NetworkError, /\Arequest to 127\.0\.0\.1 failed: /)
      expect(requests.size).to eq(1)
    end
  end

  # The server sends the response, then closes the connection. The cut rows
  # stop the body halfway. A plain body without Content-Length or chunked
  # encoding is not in the table: it ends when the connection closes, so a
  # cut is not detectable. The stream rows send the whole body, which holds
  # half a gzip stream.
  [
    { name: "a plain body with Content-Length", response: RawHTTPServer.cut(:json, :length), error: "EOFError" },
    { name: "a gzip body with Content-Length", response: RawHTTPServer.cut(:gzip, :length), error: "EOFError" },
    { name: "a chunked gzip body", response: RawHTTPServer.cut(:gzip, :chunked), error: "EOFError" },
    { name: "a gzip body without Content-Length", response: RawHTTPServer.cut(:gzip, :none),
      error: "Zlib::BufError" },
    { name: "a gzip stream in a body with Content-Length", response: RawHTTPServer.cut_gzip_stream(:length),
      error: "Zlib::BufError" },
    { name: "a gzip stream in a chunked body", response: RawHTTPServer.cut_gzip_stream(:chunked),
      error: "Zlib::BufError" }
  ].each do |example|
    it "raises NetworkError for #{example[:name]} that ends early" do
      @server = RawHTTPServer.new { [example[:response], :close] }

      expect { client.post_form(@server.url("/token"), { "grant_type" => "x" }, timeout: 2) }
        .to raise_error(Keycardai::OAuth::NetworkError, "request to 127.0.0.1 failed: #{example[:error]}")
    end
  end

  it "raises NetworkError for a response whose status line Net::HTTP cannot parse" do
    @server = RawHTTPServer.new { "not an HTTP status line\r\n\r\n" }

    expect { client.get(@server.url("/a")) }
      .to raise_error(Keycardai::OAuth::NetworkError, "request to 127.0.0.1 failed: Net::HTTPBadResponse")
  end

  it "discovery reads a 200 that does not decompress as a malformed document" do
    serve(RawHTTPServer.corrupt_gzip(200))

    expect { Keycardai::OAuth.fetch_authorization_server_metadata(@server.url(""), http_client: client) }
      .to raise_error(Keycardai::OAuth::ProtocolError, "metadata for #{@server.url("")} is not valid JSON") { |e|
        expect(e.code).to eq("invalid_metadata")
      }
  end
end
