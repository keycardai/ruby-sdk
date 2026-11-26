# frozen_string_literal: true

require "json"
require "socket"
require "zlib"

# Conformance suite for keycard-sdk-spec specs/a2a/a2a-delegation.md.
# Each example maps to a row of the spec's Unit Tests table; the multi-hop
# act-chain rows live in the integration table for the E2E phase.
RSpec.describe "A2A delegation" do
  let(:issuer) { "https://acme.test" }
  let(:target) { "https://agent-b.test" }
  let(:card) { { "name" => "agent-b", "description" => "downstream agent" } }

  def urls
    {
      zone_metadata: "#{issuer}/.well-known/oauth-authorization-server",
      token: "#{issuer}/oauth/token",
      agent_card: "#{target}/.well-known/agent-card.json",
      jsonrpc: "#{target}/a2a/jsonrpc"
    }
  end

  def http(card_response: nil, token_response: nil, rpc_response: nil, rpc_url: urls[:jsonrpc])
    routes = {
      urls[:zone_metadata] => http_json({ "issuer" => issuer, "token_endpoint" => urls[:token] }),
      urls[:token] => token_response || http_json({ "access_token" => "at_delegated" }),
      urls[:agent_card] => card_response || http_json(card),
      rpc_url => rpc_response || http_json({ "jsonrpc" => "2.0", "id" => "1", "result" => rpc_result })
    }
    FakeHTTPClient.new { |url, _params| routes[url] }
  end

  # Recorded from a keycardai-a2a (a2a-sdk 1.x) agent answering SendMessage.
  def rpc_result
    { "message" => { "messageId" => "resp-1", "contextId" => "ctx-1", "role" => "ROLE_AGENT",
                     "parts" => [{ "text" => "handled" }] } }
  end

  def client(transport, **opts)
    Keycardai::A2A::DelegationClient.new(issuer: issuer, client_id: "cid", client_secret: "csecret",
                                         http_client: transport, **opts)
  end

  it "1: discovers a healthy agent's card and serves the second lookup from cache" do
    transport = http
    discovery = Keycardai::A2A::ServiceDiscovery.new(http_client: transport)

    first = discovery.get_card(target)
    second = discovery.get_card(target)

    expect(first).to eq(card)
    expect(second).to eq(card)
    expect(transport.request_count(urls[:agent_card])).to eq(1)
  end

  it "2: a card missing name is a discovery error" do
    transport = http(card_response: http_json({ "description" => "anonymous" }))
    discovery = Keycardai::A2A::ServiceDiscovery.new(http_client: transport)

    expect { discovery.get_card(target) }.to raise_error(Keycardai::A2A::DiscoveryError)
  end

  it "3: a valid delegation exchanges the user token for the target and invokes with it" do
    transport = http
    result = client(transport).invoke(
      target: target, subject_token: "at_user", message: Keycardai::A2A.text_message("hi")
    )

    exchange = transport.calls.find { |call| call.url == urls[:token] }
    expect(exchange.params).to include(
      "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
      "subject_token" => "at_user",
      "resource" => target
    )

    rpc = transport.calls.find { |call| call.url == urls[:jsonrpc] }
    expect(rpc.headers["Authorization"]).to eq("Bearer at_delegated")
    expect(rpc.headers["A2A-Version"]).to eq("1.0")
    expect(rpc.params).to include("method" => "SendMessage")
    expect(rpc.params.dig("params", "message", "parts", 0, "text")).to eq("hi")
    expect(result.message).to eq(rpc_result)
    expect(result.agent_card).to eq(card)
  end

  # ECO-161: the wire shape per protocol generation (row 3's invocation, per
  # version). The default is the 1.0 generation keycardai-a2a serves;
  # protocol_version: "0.3" sends a real 0.3 envelope, not a 1.0 envelope
  # under a 0.3 header.
  describe "3: invocation wire shape" do
    [
      { name: "default is protocol 1.0", opts: {},
        method: "SendMessage", header: "A2A-Version", version: "1.0", absent: "X-A2A-Protocol-Version",
        role: "ROLE_USER", part: { "text" => "hi" } },
      { name: "explicit 1.0", opts: { protocol_version: Keycardai::A2A::PROTOCOL_VERSION },
        method: "SendMessage", header: "A2A-Version", version: "1.0", absent: "X-A2A-Protocol-Version",
        role: "ROLE_USER", part: { "text" => "hi" } },
      { name: "0.3 sends a 0.3 envelope", opts: { protocol_version: Keycardai::A2A::LEGACY_PROTOCOL_VERSION },
        method: "message/send", header: "X-A2A-Protocol-Version", version: "0.3", absent: "A2A-Version",
        role: "user", part: { "kind" => "text", "text" => "hi" } }
    ].each do |row|
      it row[:name] do
        transport = http
        message = Keycardai::A2A.text_message("hi")
        client(transport, **row[:opts]).invoke(target: target, subject_token: "at_user", message: message)

        rpc = transport.calls.find { |call| call.url == urls[:jsonrpc] }
        expect(rpc.headers[row[:header]]).to eq(row[:version])
        expect(rpc.headers).not_to have_key(row[:absent])
        expect(rpc.params).to include("jsonrpc" => "2.0", "method" => row[:method])
        expect(rpc.params["params"]["message"]).to eq(
          "messageId" => message["message"]["messageId"], "role" => row[:role], "parts" => [row[:part]]
        )
      end
    end

    it "never sends the 0.3 method name by default" do
      transport = http
      3.times { client(transport).invoke(target: target, subject_token: "at_user", message: Keycardai::A2A.text_message("hi")) }

      methods = transport.calls.select { |call| call.url == urls[:jsonrpc] }.map { |call| call.params["method"] }
      expect(methods).to eq(%w[SendMessage] * 3)
      expect(methods).not_to include("message/send")
    end

    it "leaves caller-built params alone on 1.0 and rejects unknown versions" do
      transport = http
      params = { "message" => { "messageId" => "m", "role" => "ROLE_USER", "parts" => [{ "text" => "x" }],
                                "metadata" => { "traceId" => "abc" } } }
      client(transport).invoke(target: target, subject_token: "at_user", message: params)
      rpc = transport.calls.find { |call| call.url == urls[:jsonrpc] }
      expect(rpc.params["params"]).to eq(params)

      expect { client(transport, protocol_version: "2.0") }.to raise_error(ArgumentError, /unsupported/)
    end

    it "returns a 1.0 task result as the agent sent it" do
      task = { "task" => { "id" => "task-1", "contextId" => "ctx-1",
                           "status" => { "state" => "TASK_STATE_COMPLETED" } } }
      transport = http(rpc_response: http_json({ "jsonrpc" => "2.0", "id" => "1", "result" => task }))

      result = client(transport).invoke(target: target, subject_token: "at_user", message: Keycardai::A2A.text_message("hi"))

      expect(result.message).to eq(task)
    end
  end

  it "4: a rejected exchange surfaces the OAuth error and the agent is not invoked" do
    transport = http(token_response: http_json({ "error" => "invalid_grant" }, status: 400))

    expect { client(transport).invoke(target: target, subject_token: "at_bad", message: {}) }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e| expect(e.error).to eq("invalid_grant") }
    expect(transport.request_count(urls[:jsonrpc])).to eq(0)
  end

  it "5: a JSON-RPC error response surfaces an invocation error" do
    transport = http(rpc_response: http_json(
      { "jsonrpc" => "2.0", "id" => "1", "error" => { "code" => -32_600, "message" => "bad request" } }
    ))

    expect { client(transport).invoke(target: target, subject_token: "at_user", message: {}) }
      .to raise_error(Keycardai::A2A::InvocationError) { |e|
        expect(e.rpc_error).to include("code" => -32_600)
      }
  end

  describe "invocation endpoint origins" do
    [
      ["12: invokes on the same origin", "https://agent-b.test/rpc", {}],
      ["14: invokes on an allowlisted origin", "https://gateway.test/rpc",
       { trusted_endpoint_origins: ["HTTPS://GATEWAY.test:443"] }],
      ["15: matches the explicit default port", "https://agent-b.test:443/rpc", {}],
      ["15b: matches scheme and host case-insensitively", "HTTPS://Agent-B.Test/rpc", {}]
    ].each do |name, endpoint, opts|
      it name do
        transport = endpoint_transport(endpoint)
        client(transport, **opts).invoke(target: target, subject_token: "at_user", message: {})

        expect(transport.request_count(urls[:token])).to eq(1)
        expect(transport.request_count(endpoint)).to eq(1)
        rpc = transport.calls.find { |call| call.url == endpoint }
        expect(rpc.headers["Authorization"]).to eq("Bearer at_delegated")
      end
    end

    [
      ["13: refuses another host", "https://other.test/rpc", "https://other.test:443", false],
      ["15: refuses another port", "https://agent-b.test:8443/rpc", "https://agent-b.test:8443", false],
      ["15: refuses another scheme", "http://agent-b.test/rpc", "http://agent-b.test:80", false],
      ["15a: refuses another origin in a 0.3 card", "https://other.test/rpc", "https://other.test:443", true]
    ].each do |name, endpoint, origin, legacy|
      it name do
        transport = endpoint_transport(endpoint, legacy: legacy)
        opts = legacy ? { protocol_version: Keycardai::A2A::LEGACY_PROTOCOL_VERSION } : {}

        expect { client(transport, **opts).invoke(target: target, subject_token: "at_user", message: {}) }
          .to raise_error(Keycardai::A2A::DiscoveryError) { |e|
            expect(e.message).to include(origin, target)
            expect(e.retryable?).to be(false)
          }
        expect(transport.calls.map(&:url)).to eq([urls[:agent_card]])
      end
    end

    def endpoint_transport(endpoint, legacy: false)
      details = if legacy
                  { "url" => endpoint }
                else
                  interface = { "url" => endpoint, "protocolBinding" => "JSONRPC", "protocolVersion" => "1.0" }
                  { "supportedInterfaces" => [interface] }
                end
      http(card_response: http_json(card.merge(details)), rpc_url: endpoint)
    end
  end

  it "honors a card-declared invocation endpoint over the convention path" do
    custom_rpc = "#{target}/custom/rpc"
    transport = FakeHTTPClient.new do |url, _params|
      case url
      when urls[:zone_metadata] then http_json({ "issuer" => issuer, "token_endpoint" => urls[:token] })
      when urls[:token] then http_json({ "access_token" => "at_delegated" })
      when urls[:agent_card] then http_json(card.merge("url" => custom_rpc))
      when custom_rpc then http_json({ "jsonrpc" => "2.0", "id" => "1", "result" => {} })
      end
    end

    client(transport).invoke(target: target, subject_token: "at_user", message: {})

    expect(transport.request_count(custom_rpc)).to eq(1)
  end

  it "invokes the JSONRPC interface of a 1.0 card matching its protocol version" do
    rpc10 = "#{target}/rpc10"
    rpc03 = "#{target}/rpc03"
    interfaces = [
      { "url" => "#{target}/grpc", "protocolBinding" => "GRPC", "protocolVersion" => "1.0" },
      { "url" => rpc03, "protocolBinding" => "JSONRPC", "protocolVersion" => "0.3" },
      { "url" => rpc10, "protocolBinding" => "JSONRPC", "protocolVersion" => "1.0" }
    ]
    transport = FakeHTTPClient.new do |url, _params|
      case url
      when urls[:zone_metadata] then http_json({ "issuer" => issuer, "token_endpoint" => urls[:token] })
      when urls[:token] then http_json({ "access_token" => "at_delegated" })
      when urls[:agent_card] then http_json(card.merge("supportedInterfaces" => interfaces))
      when rpc10, rpc03 then http_json({ "jsonrpc" => "2.0", "id" => "1", "result" => {} })
      end
    end

    client(transport).invoke(target: target, subject_token: "at_user", message: {})
    client(transport, protocol_version: "0.3").invoke(target: target, subject_token: "at_user", message: {})

    expect(transport.request_count(rpc10)).to eq(1)
    expect(transport.request_count(rpc03)).to eq(1)
  end

  it "expires cached cards after the TTL" do
    transport = http
    clock_time = { now: Time.now }
    discovery = Keycardai::A2A::ServiceDiscovery.new(http_client: transport, cache_ttl: 900,
                                                     clock: -> { clock_time[:now] })
    discovery.get_card(target)
    clock_time[:now] += 901
    discovery.get_card(target)

    expect(transport.request_count(urls[:agent_card])).to eq(2)
  end
end

# Rows 9 to 11: the default peer transports against a local server.
RSpec.describe "A2A delegation peer reply size" do
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
