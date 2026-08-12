# frozen_string_literal: true

# Agent A, the calling agent. On POST /delegate it takes the inbound user's
# bearer token, discovers agent B's card, exchanges the token for one scoped
# to B (RFC 8693, the user stays the subject), and invokes B.
#
# Two token sources, in order:
#   1. An inbound Authorization header, which is the real delegation path.
#   2. KEYCARD_IMPERSONATE_USER, for headless runs with no inbound user. A
#      Keycard zone will not re-exchange a substitute-user token, so this path
#      impersonates directly for B rather than exchanging.

require "json"
require "keycardai/a2a"

KEYCARD_URL = ENV.fetch("KEYCARD_URL") { abort "KEYCARD_URL is required" }
CLIENT_ID = ENV.fetch("KEYCARD_CLIENT_ID") { abort "KEYCARD_CLIENT_ID is required" }
CLIENT_SECRET = ENV.fetch("KEYCARD_CLIENT_SECRET") { abort "KEYCARD_CLIENT_SECRET is required" }
AGENT_B_URL = ENV.fetch("AGENT_B_URL", "http://127.0.0.1:9601")
IMPERSONATE = ENV["KEYCARD_IMPERSONATE_USER"]

credentials = { client_id: CLIENT_ID, client_secret: CLIENT_SECRET }
delegation = Keycardai::A2A::DelegationClient.new(issuer: KEYCARD_URL, **credentials)
exchange = Keycardai::OAuth::TokenExchangeClient.new(issuer: KEYCARD_URL, **credentials)
discovery = Keycardai::A2A::ServiceDiscovery.new

def json(status, payload) = [status, { "content-type" => "application/json" }, [JSON.dump(payload)]]

delegate = lambda do |env|
  body = env["rack.input"].read
  text = body.empty? ? "hello from agent-a" : (JSON.parse(body)["text"] || "hello from agent-a")
  inbound = env["HTTP_AUTHORIZATION"].to_s[/\ABearer (.+)\z/i, 1]

  if inbound
    result = delegation.invoke(target: AGENT_B_URL, subject_token: inbound,
                              message: Keycardai::A2A.text_message(text))
    json(200, { "path" => "delegated-exchange", "agent_b" => result.message,
                "agent_card" => result.agent_card["name"] })
  elsif IMPERSONATE
    # No inbound user: mint a token for B directly on the user's behalf, then
    # invoke B through the same discovery and JSON-RPC path.
    token = exchange.impersonate(user_identifier: IMPERSONATE, resource: AGENT_B_URL)
    card = discovery.get_card(AGENT_B_URL)
    rpc = Keycardai::OAuth::HTTP::NetHTTPClient.new.post_json(
      card["url"] || "#{AGENT_B_URL}#{Keycardai::A2A::JSONRPC_PATH}",
      { "jsonrpc" => "2.0", "id" => "1", "method" => Keycardai::A2A::MESSAGE_SEND_METHOD,
        "params" => Keycardai::A2A.text_message(text) },
      headers: { "Authorization" => "Bearer #{token.access_token}",
                 "X-A2A-Protocol-Version" => Keycardai::A2A::PROTOCOL_VERSION },
    )
    json(200, { "path" => "impersonation", "agent_b" => JSON.parse(rpc.body)["result"],
                "agent_card" => card["name"] })
  else
    json(400, { "error" => "no inbound bearer token and no KEYCARD_IMPERSONATE_USER" })
  end
rescue Keycardai::Error => e
  json(502, { "error" => e.class.name, "message" => e.message })
end

run lambda { |env|
  case env["PATH_INFO"]
  when "/healthz" then json(200, { "status" => "ok", "agent" => "a" })
  when "/delegate" then delegate.call(env)
  else json(404, { "error" => "not_found" })
  end
}
