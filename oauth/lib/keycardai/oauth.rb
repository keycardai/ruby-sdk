# frozen_string_literal: true

require_relative "oauth/version"
require_relative "oauth/errors"
require_relative "oauth/http"
require_relative "oauth/jwks_keyring"
require_relative "oauth/jwt_signer"
require_relative "oauth/jwt_verifier"

# Root namespace shared by all Keycard gems.
module Keycardai
  # OAuth 2.0 primitives for the Keycard platform: token exchange (RFC 8693),
  # client credentials, authorization code + PKCE, dynamic client registration
  # (RFC 7591), authorization server discovery (RFC 8414), JWT/JWKS
  # verification, application credentials, and AccessContext.
  #
  # Contract: https://github.com/keycardai/keycard-sdk-spec
  module OAuth
  end
end
