# frozen_string_literal: true

require "json"
require "socket"
require "zlib"

# Default transport conformance against a local server.
RSpec.describe "A2A response size" do
  let(:peer_limit) { 64 * 1024 * 1024 }
  let(:limit) { Keycardai::OAuth::MAX_RESPONSE_BODY_BYTES }
  let(:oversized) { "x" * (limit + 1024) }
  let(:requests) { Queue.new }
  let(:reply_type) { Data.define(:status, :encoding, :body) }

  def card_for(base)
    { "name" => "agent-b", "url" => "#{base}/a2a/jsonrpc" }
  end

  def routes(base, card: card_for(base), token: { "access_token" => "at_delegated" },
             rpc: { "jsonrpc" => "2.0", "id" => "1", "result" => { "text" => "handled" } })
    {
      "/.well-known/oauth-authorization-server" => { "issuer" => base, "token_endpoint" => "#{base}/oauth/token" },
      "/oauth/token" => token,
      "/.well-known/agent-card.json" => card,
      "/a2a/jsonrpc" => rpc
    }
  end

  def read_path(socket)
    request_line = socket.gets or return
    length = 0
    while (line = socket.gets) && line != "\r\n"
      name, value = line.split(":", 2)
      length = value.to_i if name.casecmp?("content-length")
    end
    socket.read(length) if length.positive?
    request_line.split[1]
  end

  def serve(socket, table)
    path = read_path(socket) or return
    requests << path
    reply = table.call.fetch(path)
    reply = reply_type.new(200, "identity", JSON.dump(reply)) unless reply.is_a?(reply_type)
    socket.write("HTTP/1.1 #{reply.status} Result\r\nContent-Type: application/json\r\n" \
                 "Content-Length: #{reply.body.bytesize}\r\nContent-Encoding: #{reply.encoding}\r\n" \
                 "Connection: close\r\n\r\n")
    socket.write(reply.body)
  rescue IOError, SystemCallError
    nil
  ensure
    socket.close
  end

  def with_server(build_routes)
    server = TCPServer.new("127.0.0.1", 0)
    base = "http://127.0.0.1:#{server.addr[1]}"
    table = -> { build_routes.call(base) }
    thread = Thread.new { loop { Thread.new(server.accept) { |socket| serve(socket, table) } } }
    yield base
  ensure
    thread&.kill
    server&.close
  end

  def client(base, **options)
    Keycardai::A2A::DelegationClient.new(issuer: base, client_id: "cid", client_secret: "csecret", **options)
  end

  def fetch_peer(base, kind, **options)
    return Keycardai::A2A::ServiceDiscovery.new(**options).get_card(base) if kind == :card

    client(base, **options).invoke(target: base, subject_token: "user-token", message: Keycardai::A2A.text_message("hi"))
  end

  def peer_reply(kind, bytes:, status: 200, gzip: false)
    json = kind == :card ? '{"name":"agent-b"}' : '{"jsonrpc":"2.0","id":"1","result":{"text":"handled"}}'
    body = json + (" " * bytes)
    reply_type.new(status, gzip ? "gzip" : "identity", gzip ? Zlib.gzip(body) : body)
  end

  def with_peer_reply(kind, **options, &block)
    reply = peer_reply(kind, **options)
    with_server(->(base) { routes(base, **{ kind => reply }) }, &block)
  end

  def requested_paths
    Array.new(requests.size) { requests.pop }
  end

  it "9: returns an agent reply over 1 MiB" do
    reply = { "jsonrpc" => "2.0", "id" => "1", "result" => { "text" => oversized } }
    with_server(->(base) { routes(base, rpc: reply) }) do |base|
      result = client(base).invoke(target: base, subject_token: "user-token", message: Keycardai::A2A.text_message("hi"))

      expect(result.message["text"].bytesize).to eq(oversized.bytesize)
    end
  end

  it "9: discovers an agent card over 1 MiB" do
    with_server(->(base) { routes(base, card: card_for(base).merge("description" => oversized)) }) do |base|
      card = Keycardai::A2A::ServiceDiscovery.new.get_card(base)

      expect(card["description"].bytesize).to eq(oversized.bytesize)
    end
  end

  it "11: rejects a token-exchange response over 1 MiB and does not invoke the agent" do
    token = { "access_token" => "at_delegated", "padding" => oversized }
    with_server(->(base) { routes(base, token: token) }) do |base|
      expect do
        fetch_peer(base, :rpc, max_peer_response_bytes: peer_limit + 1024)
      end.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) { |error| expect(error.limit).to eq(limit) }
      expect(requested_paths).not_to include("/a2a/jsonrpc")
    end
  end

  %i[card rpc].each do |kind|
    it "10: bounds decoded gzip bytes in the #{kind} reply" do
      with_peer_reply(kind, bytes: 2048, gzip: true) do |base|
        expect { fetch_peer(base, kind, max_peer_response_bytes: 512) }
          .to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) { |error| expect(error.code).to eq("invalid_response") }
      end
    end

    [200, 429, 503].each do |status|
      it "10a: preserves status and retryability for an oversized #{kind} reply with HTTP #{status}" do
        with_peer_reply(kind, bytes: 1024, status: status) do |base|
          expect { fetch_peer(base, kind, max_peer_response_bytes: 512) }
            .to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |error|
              expect(error).to have_attributes(code: "invalid_response", status: status,
                                               retryable?: kind == :card || status != 200)
            end
        end
      end
    end

    it "11: lowers or raises the default decoded limit for the #{kind} reply" do
      with_peer_reply(kind, bytes: 512) do |base|
        expect(fetch_peer(base, kind)).not_to be_nil
        expect { fetch_peer(base, kind, max_peer_response_bytes: 128) }
          .to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError)
      end
      with_peer_reply(kind, bytes: peer_limit) do |base|
        expect { fetch_peer(base, kind) }.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) do |error|
          expect(error).to have_attributes(code: "invalid_response", limit: peer_limit)
        end
        expect(fetch_peer(base, kind, max_peer_response_bytes: peer_limit + 1024)).not_to be_nil
      end
    end
  end
end
