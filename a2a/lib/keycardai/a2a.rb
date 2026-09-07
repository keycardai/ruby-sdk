# frozen_string_literal: true

require "keycardai/oauth"
require_relative "a2a/version"
require_relative "a2a/errors"
require_relative "a2a/wire"
require_relative "a2a/service_discovery"
require_relative "a2a/delegation_client"

module Keycardai
  # Agent-to-agent delegation: one agent calls another on the user's behalf.
  # Discover the target's agent card, exchange the user's token for one scoped
  # to the target (RFC 8693; the user stays the subject, the authorization
  # server records the caller in the token's act chain), and invoke the target
  # over JSON-RPC.
  #
  # Contract: https://github.com/keycardai/keycard-sdk-spec
  module A2A
    # Well-known path of an agent's card, relative to its base URL.
    AGENT_CARD_PATH = "/.well-known/agent-card.json"

    # JSON-RPC invocation path, relative to an agent's base URL.
    JSONRPC_PATH = "/a2a/jsonrpc"

    # The protocol-generation constants (PROTOCOL_VERSION, MESSAGE_SEND_METHOD,
    # ROLE_USER, and their LEGACY_ 0.3 counterparts) live in a2a/wire.rb.
  end
end
