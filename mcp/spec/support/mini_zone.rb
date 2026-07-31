# frozen_string_literal: true

# A minimal zone for grant/metadata tests: discovery plus a token endpoint.
class MiniZone
  attr_reader :issuer, :metadata_url, :token_url

  def initialize(issuer: "https://acme.test")
    @issuer = issuer
    @metadata_url = "#{issuer}/.well-known/oauth-authorization-server"
    @token_url = "#{issuer}/oauth/token"
  end

  def metadata(overrides = {})
    { "issuer" => @issuer, "token_endpoint" => @token_url,
      "authorization_endpoint" => "#{@issuer}/oauth/authorize" }.merge(overrides)
  end
end
