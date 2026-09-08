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

  it "applies the timeout per request and restores the defaults when absent" do
    client.get("https://zone.example/a", timeout: 2.5)
    session = sessions.first
    expect([session.open_timeout, session.read_timeout]).to eq([2.5, 2.5])

    client.get("https://zone.example/b")
    expect([session.open_timeout, session.read_timeout]).to eq([60, 60])
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
