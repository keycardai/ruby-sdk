# frozen_string_literal: true

# A TokenVerifier stand-in: returns the configured AccessToken for known
# tokens and raises InvalidTokenError otherwise.
class FakeVerifier
  def initialize(tokens = {})
    @tokens = tokens
  end

  def verify_token(token)
    @tokens[token] || raise(Keycardai::OAuth::InvalidTokenError, "token signature does not validate")
  end
end

def access_token(token: "at_valid", scope: "mcp:tools", client_id: "client_abc",
                 sub: "usr_123", sub_profile: "user", keycard_app_id: "app_abc")
  claims = {
    "iss" => "https://acme.test", "sub" => sub, "aud" => "https://tool.example.com",
    "exp" => Time.now.to_i + 300, "iat" => Time.now.to_i, "client_id" => client_id,
    "scope" => scope, "sub_profile" => sub_profile, "keycard_app_id" => keycard_app_id
  }
  # A non-Keycard token carries neither Keycard claim; nil drops them so a
  # caller can build that case.
  Keycardai::OAuth::AccessToken.new(token: token, claims: claims.compact)
end
