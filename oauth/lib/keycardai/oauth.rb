# frozen_string_literal: true

require_relative "oauth/version"

# Root namespace shared by all Keycard gems.
module Keycardai
  # Root of the Keycard error taxonomy. Every error raised by any Keycard gem
  # is a subclass, so `rescue Keycardai::Error` catches the whole family.
  class Error < StandardError; end

  # OAuth 2.0 primitives for the Keycard platform: token exchange (RFC 8693),
  # client credentials, authorization code + PKCE, dynamic client registration
  # (RFC 7591), authorization server discovery (RFC 8414), JWT/JWKS
  # verification, application credentials, and AccessContext.
  #
  # Contract: https://github.com/keycardai/keycard-sdk-spec
  module OAuth
  end
end
