# frozen_string_literal: true

require "jwt"
require "openssl"

# Decode one base64url JWT segment into its JSON document.
def decode_jwt_part(part)
  padded = part.tr("-_", "+/")
  padded += "=" * ((4 - (padded.length % 4)) % 4)
  JSON.parse(padded.unpack1("m0"))
end

# An in-memory Keycard zone for conformance tests: an issuer with RSA signing
# keys, RFC 8414 metadata, and a JWKS document, wired to a FakeHTTPClient.
class ZoneFixture
  attr_reader :issuer, :metadata_url, :jwks_url

  def initialize(issuer: "https://acme.test", kids: ["kid-1"])
    @issuer = issuer
    @metadata_url = "#{issuer}/.well-known/oauth-authorization-server"
    @jwks_url = "#{issuer}/.well-known/jwks.json"
    @keys = kids.to_h { |kid| [kid, OpenSSL::PKey::RSA.new(2048)] }
  end

  def private_key(kid = @keys.each_key.first)
    @keys.fetch(kid)
  end

  def metadata(jwks_uri: @jwks_url)
    { "issuer" => @issuer, "jwks_uri" => jwks_uri }
  end

  def jwks
    keys = @keys.map do |kid, key|
      JWT::JWK.new(key.public_key, { kid: kid, use: "sig", alg: "RS256" }).export.transform_keys(&:to_s)
    end
    { "keys" => keys }
  end

  # A FakeHTTPClient serving this zone's metadata and JWKS. Override either
  # response by passing a handler for that URL.
  def http_client(overrides = {})
    FakeHTTPClient.new do |url|
      if overrides.key?(url)
        overrides.fetch(url).call
      elsif url == @metadata_url
        json_response(metadata)
      elsif url == @jwks_url
        json_response(jwks)
      else
        Keycardai::OAuth::HTTP::Response.new(status: 404, headers: {}, body: "")
      end
    end
  end

  def token(claims = {}, kid: @keys.each_key.first, header_overrides: {})
    defaults = {
      "iss" => @issuer,
      "sub" => "usr_123",
      "aud" => "https://api.acme.test",
      "exp" => Time.now.to_i + 300,
      "iat" => Time.now.to_i,
      "client_id" => "client_abc"
    }
    JWT.encode(defaults.merge(claims), private_key(kid), "RS256", { "kid" => kid }.merge(header_overrides))
  end
end
