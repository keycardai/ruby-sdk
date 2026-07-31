# frozen_string_literal: true

require "keycardai/oauth"
require_relative "mcp/version"

module Keycardai
  # Keycard integration for MCP servers, attached at the Rack seam: bearer
  # middleware (RFC 6750), OAuth metadata endpoints (RFC 9728 / RFC 8414), and
  # an AuthProvider for delegated token exchange. Handlers read the verified
  # identity and exchanged tokens from the Rack env.
  #
  # Contract: https://github.com/keycardai/keycard-sdk-spec
  module MCP
    # Rack env key holding the verified inbound token's AuthInfo.
    ENV_AUTH_INFO = "keycardai.auth_info"

    # Rack env key holding the AccessContext produced by grant middleware.
    ENV_ACCESS_CONTEXT = "keycardai.access_context"
  end
end
