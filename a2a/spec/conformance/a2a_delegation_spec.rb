# frozen_string_literal: true

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

  def http(card_response: nil, token_response: nil, rpc_response: nil)
    routes = {
      urls[:zone_metadata] => http_json({ "issuer" => issuer, "token_endpoint" => urls[:token] }),
      urls[:token] => token_response || http_json({ "access_token" => "at_delegated" }),
      urls[:agent_card] => card_response || http_json(card),
      urls[:jsonrpc] => rpc_response ||
                        http_json({ "jsonrpc" => "2.0", "id" => "1", "result" => { "kind" => "message" } })
    }
    FakeHTTPClient.new { |url, _params| routes[url] }
  end

  def client(transport)
    Keycardai::A2A::DelegationClient.new(issuer: issuer, client_id: "cid", client_secret: "csecret",
                                         http_client: transport)
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
    expect(rpc.headers["X-A2A-Protocol-Version"]).to eq("0.3")
    expect(rpc.params).to include("method" => "message/send")
    expect(rpc.params.dig("params", "message", "parts", 0, "text")).to eq("hi")
    expect(result.message).to eq({ "kind" => "message" })
    expect(result.agent_card).to eq(card)
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
