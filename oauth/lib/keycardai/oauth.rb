# frozen_string_literal: true

require_relative "oauth/version"
require_relative "oauth/errors"
require_relative "oauth/http"
require_relative "oauth/discovery"
require_relative "oauth/token_types"
require_relative "oauth/token_requests"
require_relative "oauth/substitute_user"
require_relative "oauth/pkce"
require_relative "oauth/authorization_code"
require_relative "oauth/authenticate"
require_relative "oauth/registration"
require_relative "oauth/client_secret"
require_relative "oauth/private_key"
require_relative "oauth/web_identity"
require_relative "oauth/workload_identity"
require_relative "oauth/token_sources"
require_relative "oauth/access_context"
require_relative "oauth/exchange_tokens"
require_relative "oauth/token_verifier"
require_relative "oauth/token_exchange_client"
require_relative "oauth/client_credentials_client"
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
