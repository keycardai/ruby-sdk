# frozen_string_literal: true

# Agent B, the downstream agent. Publishes its agent card and a
# bearer-protected JSON-RPC endpoint, and reports the subject it verified so a
# caller can prove the user's identity survived the hop.
#
# Audience binding is the security property on display: the verifier accepts
# only tokens minted for this agent's own identifier, so a token issued for
# someone else is rejected even though it is signed by the same zone.

require "json"
require "keycardai/a2a"
require "keycardai/mcp"

KEYCARD_URL = ENV.fetch("KEYCARD_URL") { abort "KEYCARD_URL is required" }
AGENT_B_URL = ENV.fetch("AGENT_B_URL", "http://127.0.0.1:9601")

verifier = Keycardai::OAuth::TokenVerifier.new(issuers: KEYCARD_URL, audiences: AGENT_B_URL)

AGENT_CARD = {
  "name" => "agent-b",
  "description" => "Downstream agent that reports which user it was called for",
  "version" => "0.1.0",
  "protocolVersion" => Keycardai::A2A::PROTOCOL_VERSION,
  "url" => "#{AGENT_B_URL}#{Keycardai::A2A::JSONRPC_PATH}",
  "capabilities" => { "streaming" => false },
  "skills" => [{ "id" => "echo", "name" => "echo", "description" => "Echo a message back with the caller's identity" }],
}.freeze

jsonrpc = lambda do |env|
  request = JSON.parse(env["rack.input"].read)
  auth = Keycardai::MCP.auth_info(env)
  text = request.dig("params", "message", "parts", 0, "text")

  result = {
    "kind" => "message",
    "role" => "agent",
    "parts" => [{ "kind" => "text", "text" => "agent-b handled #{text.inspect}" }],
    # The proof of identity flow-through: B independently verified the token
    # and this is the subject it saw, not something the caller asserted.
    "verifiedSubject" => auth.subject,
    "verifiedAudience" => auth.audiences,
    "verifiedActor" => auth.claims["act"],
  }
  [200, { "content-type" => "application/json" },
   [JSON.dump({ "jsonrpc" => "2.0", "id" => request["id"], "result" => result })]]
end

protected_jsonrpc = Keycardai::MCP::RequireBearerAuth.new(jsonrpc, verifier: verifier)

run lambda { |env|
  case env["PATH_INFO"]
  when "/healthz"
    [200, { "content-type" => "application/json" }, [JSON.dump({ "status" => "ok", "agent" => "b" })]]
  when Keycardai::A2A::AGENT_CARD_PATH
    [200, { "content-type" => "application/json" }, [JSON.dump(AGENT_CARD)]]
  when Keycardai::A2A::JSONRPC_PATH
    protected_jsonrpc.call(env)
  else
    [404, { "content-type" => "application/json" }, [JSON.dump({ "error" => "not_found" })]]
  end
}
