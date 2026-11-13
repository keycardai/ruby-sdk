# frozen_string_literal: true

# NetHTTPClient session reuse, stubbed at the Net::HTTP seam. The shared
# FakeHTTPClient replaces the transport entirely and cannot observe sessions,
# so these specs fake Net::HTTP.new itself. No network.
RSpec.describe Keycardai::OAuth::HTTP::NetHTTPClient do
  # Stands in for a Net::HTTP session: tracks started state, timeouts, and
  # the requests it served.
  fake_session = Class.new do
    attr_reader :host, :port, :requests
    attr_accessor :use_ssl, :open_timeout, :read_timeout, :fail_with

    def initialize(host, port)
      @host = host
      @port = port
      @started = false
      @requests = []
      @open_timeout = 60
      @read_timeout = 60
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
      Struct.new(:code, :to_hash, :body).new("200", { "content-type" => ["application/json"] }, "{}")
    end
  end

  let(:sessions) { [] }
  let(:client) { described_class.new }

  before do
    allow(Net::HTTP).to receive(:new) do |host, port|
      fake_session.new(host, port).tap { |s| sessions << s }
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
    expect([session.open_timeout, session.read_timeout]).to eq([2.5, 2.5])

    client.get("https://zone.example/b")
    expect([session.open_timeout, session.read_timeout]).to eq([10, 10])
  end

  it "a request with no timeout never inherits Net::HTTP's 60 second default" do
    client.get("https://zone.example/a")
    session = sessions.first
    expect([session.open_timeout, session.read_timeout]).to eq([10, 10])
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

  it "wraps transport failures into NetworkError with the unchanged message" do
    client.get("https://zone.example/a")
    sessions.first.fail_with = EOFError.new("end of file reached")

    expect { client.get("https://zone.example/a") }
      .to raise_error(Keycardai::OAuth::NetworkError, "request to zone.example failed: EOFError")
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
  # server keeps connections open, so +connections+ shows whether the client
  # opened a new one.
  [
    { name: "a 200 with a gzip body that does not decompress", response: RawHTTPServer.corrupt_gzip(200),
      status: 200, body: "", body_error: Zlib::DataError, connections: 2 },
    { name: "a 503 with a gzip body that does not decompress", response: RawHTTPServer.corrupt_gzip(503),
      status: 503, body: "", body_error: Zlib::DataError, connections: 2 },
    { name: "a 200 with a gzip body", response: RawHTTPServer.gzip_json(200, { "ok" => true }),
      status: 200, body: '{"ok":true}', body_error: NilClass, connections: 1 }
  ].each do |example|
    it "returns #{example[:name]} with its status, and the next POST on the client succeeds" do
      serve(example[:response], RawHTTPServer.json(200, { "next" => true }))

      response = client.post_form(@server.url("/token"), { "grant_type" => "x" })
      following = client.post_form(@server.url("/next"), { "grant_type" => "x" })

      expect(response).to have_attributes(status: example[:status], body: example[:body])
      expect(response.body_error).to be_an_instance_of(example[:body_error])
      expect(following).to have_attributes(status: 200, body: '{"next":true}')
      expect(@server.connections).to eq(example[:connections])
    end
  end

  it "discovery reads a 200 that does not decompress as a malformed document" do
    serve(RawHTTPServer.corrupt_gzip(200))

    expect { Keycardai::OAuth.fetch_authorization_server_metadata(@server.url(""), http_client: client) }
      .to raise_error(Keycardai::OAuth::ProtocolError, "metadata for #{@server.url("")} is not valid JSON") { |e|
        expect(e.code).to eq("invalid_metadata")
      }
  end
end
