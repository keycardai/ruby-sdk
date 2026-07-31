# frozen_string_literal: true

# An MCP server built on the official mcp gem, protected by keycardai-mcp:
# bearer verification, OAuth discovery metadata, and a scope-gated /mcp
# endpoint. Configuration is read here, in application code, and passed to
# the SDK explicitly; the SDK itself reads no environment variables.

require "json"
require "keycardai/mcp"
require "mcp"

KEYCARD_URL = ENV.fetch("KEYCARD_URL") { abort("KEYCARD_URL is required (the zone issuer URL)") }
RESOURCE_ID = ENV.fetch("KEYCARD_RESOURCE_ID", "mcp-server-ruby")

mcp_server = MCP::Server.new(name: RESOURCE_ID, version: "0.1.0")
mcp_server.define_tool(
  name: "hello",
  description: "Say hello from a Keycard-protected MCP server",
  input_schema: { properties: { name: { type: "string" } }, required: [] },
) do |name: "world", server_context: nil|
  MCP::Tool::Response.new([{ type: "text", text: "Hello, #{name}!" }])
end

verifier = Keycardai::OAuth::TokenVerifier.new(issuers: KEYCARD_URL)
metadata = Keycardai::MCP::MetadataApp.new(
  issuer: KEYCARD_URL,
  resource_name: RESOURCE_ID,
  scopes_supported: ["mcp:tools"],
)

mcp_endpoint = lambda do |env|
  body = env["rack.input"].read
  [200, { "content-type" => "application/json" }, [mcp_server.handle_json(body)]]
end
protected_mcp = Keycardai::MCP::RequireBearerAuth.new(
  mcp_endpoint, verifier: verifier, required_scopes: ["mcp:tools"],
)

run lambda { |env|
  case env["PATH_INFO"]
  when "/healthz"
    [200, { "content-type" => "application/json" }, [JSON.dump({ "status" => "ok" })]]
  when %r{\A/\.well-known/}
    metadata.call(env)
  when "/mcp"
    protected_mcp.call(env)
  else
    [404, { "content-type" => "application/json" }, [JSON.dump({ "error" => "not_found" })]]
  end
}
