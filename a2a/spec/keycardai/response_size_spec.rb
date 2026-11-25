# frozen_string_literal: true

require "json"
require "socket"

# The default transports against a local server: peer-agent replies have no
# size limit, and authorization-server responses keep the 1 MiB cap.
RSpec.describe "A2A response size" do
  let(:limit) { Keycardai::OAuth::MAX_RESPONSE_BODY_BYTES }
  let(:oversized) { "x" * (limit + 1024) }
  let(:requests) { Queue.new }

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
    body = JSON.dump(table.call.fetch(path))
    socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\n" \
                 "Connection: close\r\n\r\n#{body}")
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

  def client(base)
    Keycardai::A2A::DelegationClient.new(issuer: base, client_id: "cid", client_secret: "csecret")
  end

  def requested_paths
    Array.new(requests.size) { requests.pop }
  end

  it "returns an agent reply over 1 MiB" do
    reply = { "jsonrpc" => "2.0", "id" => "1", "result" => { "text" => oversized } }
    with_server(->(base) { routes(base, rpc: reply) }) do |base|
      result = client(base).invoke(target: base, subject_token: "user-token", message: Keycardai::A2A.text_message("hi"))

      expect(result.message["text"].bytesize).to eq(oversized.bytesize)
    end
  end

  it "discovers an agent card over 1 MiB" do
    with_server(->(base) { routes(base, card: card_for(base).merge("description" => oversized)) }) do |base|
      card = Keycardai::A2A::ServiceDiscovery.new.get_card(base)

      expect(card["description"].bytesize).to eq(oversized.bytesize)
    end
  end

  it "rejects a token-exchange response over 1 MiB and does not invoke the agent" do
    token = { "access_token" => "at_delegated", "padding" => oversized }
    with_server(->(base) { routes(base, token: token) }) do |base|
      expect do
        client(base).invoke(target: base, subject_token: "user-token", message: Keycardai::A2A.text_message("hi"))
      end.to raise_error(Keycardai::OAuth::ResponseBodyTooLargeError) { |error| expect(error.limit).to eq(limit) }
      expect(requested_paths).not_to include("/a2a/jsonrpc")
    end
  end
end
