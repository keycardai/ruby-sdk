# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/jwt-jwks/jwt-signing-and-verification.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe "JWT signing and verification" do
  let(:zone) { ZoneFixture.new }

  # A keyring double serving the zone's public keys and recording lookups, so
  # "no key lookup occurs" assertions are direct.
  let(:keyring) do
    lookups = []
    zone_ref = zone
    Class.new do
      define_method(:initialize) { @lookups = lookups }
      attr_reader :lookups

      define_method(:key) do |issuer, kid|
        @lookups << [issuer, kid]
        raise Keycardai::OAuth::JWKSKeyNotFoundError, "unknown kid" unless kid == "kid-1"

        zone_ref.private_key.public_key
      end
    end.new
  end

  def verifier(**options)
    defaults = { issuers: zone.issuer, keyring: keyring }
    Keycardai::OAuth::JWTVerifier.new(**defaults, **options)
  end

  def signer(**options)
    defaults = { key: zone.private_key, kid: "kid-1" }
    Keycardai::OAuth::JWTSigner.new(**defaults, **options)
  end

  def forge_token(header, claims, signature: "sig")
    encode = ->(part) { [JSON.dump(part)].pack("m0").tr("+/", "-_").delete("=") }
    "#{encode.call(header)}.#{encode.call(claims)}.#{[signature].pack("m0").tr("+/", "-_").delete("=")}"
  end

  describe Keycardai::OAuth::JWTSigner do
    it "1: fills iss from the signer's issuer when claims omit it, with kid and RS256 in the header" do
      token = signer(issuer: zone.issuer).sign({ "sub" => "usr_123" })
      header, claims = token.split(".").first(2).map { |part| decode_jwt_part(part) }

      expect(claims["iss"]).to eq(zone.issuer)
      expect(header).to include("alg" => "RS256", "kid" => "kid-1")
    end

    it "2: preserves an iss already present in the claims" do
      token = signer(issuer: zone.issuer).sign({ "iss" => "https://other.test" })
      claims = decode_jwt_part(token.split(".")[1])

      expect(claims["iss"]).to eq("https://other.test")
    end

    it "3: a signed token round-trips through a verifier trusting the issuer" do
      claims = {
        "iss" => zone.issuer, "sub" => "usr_123", "aud" => "https://api.acme.test",
        "exp" => Time.now.to_i + 300, "iat" => Time.now.to_i, "client_id" => "client_abc"
      }
      token = signer.sign(claims)

      expect(verifier.verify(token)).to include(claims)
    end
  end

  describe Keycardai::OAuth::JWTVerifier do
    it "4: returns the claims for a valid token from a trusted issuer with a resolvable kid" do
      expect(verifier.verify(zone.token)).to include("iss" => zone.issuer, "client_id" => "client_abc")
    end

    it "5: rejects alg none before any key lookup" do
      token = forge_token({ "alg" => "none", "kid" => "kid-1" }, { "iss" => zone.issuer })

      expect { verifier.verify(token) }.to raise_error(Keycardai::OAuth::InvalidTokenError)
      expect(keyring.lookups).to be_empty
    end

    it "6: rejects an alg outside the allowlist" do
      token = forge_token({ "alg" => "HS256", "kid" => "kid-1" }, { "iss" => zone.issuer })

      expect { verifier.verify(token) }.to raise_error(Keycardai::OAuth::InvalidTokenError)
    end

    it "7: rejects an untrusted iss with no key lookup and no network I/O" do
      intruder = ZoneFixture.new(issuer: "https://intruder.test")

      expect { verifier.verify(intruder.token) }.to raise_error(Keycardai::OAuth::InvalidTokenError)
      expect(keyring.lookups).to be_empty
    end

    it "8: rejects a token with no exp claim" do
      claims = decode_jwt_part(zone.token.split(".")[1]).tap { |c| c.delete("exp") }
      token = forge_token({ "alg" => "RS256", "kid" => "kid-1" }, claims)

      expect { verifier.verify(token) }.to raise_error(Keycardai::OAuth::InvalidTokenError, /exp/)
    end

    it "9: rejects a token expired beyond clock_skew" do
      token = zone.token({ "exp" => Time.now.to_i - 120 })

      expect { verifier.verify(token) }.to raise_error(Keycardai::OAuth::InvalidTokenError, /expired/)
    end

    it "10: rejects a token whose nbf is in the future beyond clock_skew" do
      token = zone.token({ "nbf" => Time.now.to_i + 120 })

      expect { verifier.verify(token) }.to raise_error(Keycardai::OAuth::InvalidTokenError, /not yet valid/)
    end

    it "11: with audiences configured, rejects a token missing aud" do
      token = zone.token.then do |signed|
        claims = decode_jwt_part(signed.split(".")[1]).tap { |c| c.delete("aud") }
        forge_token({ "alg" => "RS256", "kid" => "kid-1" }, claims)
      end

      expect { verifier(audiences: "https://api.acme.test").verify(token) }
        .to raise_error(Keycardai::OAuth::InvalidTokenError)
    end

    it "12: with audiences configured, rejects an aud with no intersection" do
      token = zone.token({ "aud" => "https://other-api.test" })

      expect { verifier(audiences: "https://api.acme.test").verify(token) }
        .to raise_error(Keycardai::OAuth::InvalidTokenError, /audience/)
    end

    it "13: rejects a token whose header has no kid" do
      claims = decode_jwt_part(zone.token.split(".")[1])
      token = forge_token({ "alg" => "RS256" }, claims)

      expect { verifier.verify(token) }.to raise_error(Keycardai::OAuth::InvalidTokenError, /kid/)
    end

    it "14: rejects a tampered signature" do
      parts = zone.token.split(".")
      parts[2] = parts[2].reverse
      tampered = parts.join(".")

      expect { verifier.verify(tampered) }.to raise_error(Keycardai::OAuth::InvalidTokenError, /signature/)
    end

    it "15: accepts a token whose exp is just past now but within clock_skew" do
      token = zone.token({ "exp" => Time.now.to_i - 10 })

      expect(verifier(clock_skew: 60).verify(token)).to include("client_id" => "client_abc")
    end

    it "rejects a malformed token that is not three parts" do
      expect { verifier.verify("not-a-jwt") }.to raise_error(Keycardai::OAuth::InvalidTokenError)
    end

    describe "construction" do
      it "raises a configuration error with no trusted issuer" do
        expect { verifier(issuers: []) }.to raise_error(Keycardai::OAuth::ConfigurationError)
      end

      it "raises a configuration error for an unimplemented algorithm" do
        expect { verifier(algorithms: ["ES256"]) }.to raise_error(Keycardai::OAuth::ConfigurationError)
      end
    end
  end
end
