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

def access_token(token: "at_valid", scope: "mcp:tools", client_id: "client_abc")
  Keycardai::OAuth::AccessToken.new(
    token: token,
    claims: {
      "iss" => "https://acme.test", "sub" => "usr_123", "aud" => "https://tool.example.com",
      "exp" => Time.now.to_i + 300, "iat" => Time.now.to_i, "client_id" => client_id, "scope" => scope
    }
  )
end
