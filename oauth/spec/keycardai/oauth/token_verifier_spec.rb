# frozen_string_literal: true

RSpec.describe Keycardai::OAuth::TokenVerifier do
  let(:zone) { ZoneFixture.new }

  def build(**options)
    described_class.new(issuers: zone.issuer, http_client: zone.http_client, **options)
  end

  describe "construction without audiences" do
    it "warns exactly once, naming audiences:" do
      expect { build }
        .to output(/warning: Keycardai::OAuth::TokenVerifier has no audiences configured.*pass audiences:/)
        .to_stderr
    end

    it "still accepts a token minted for another resource" do
      verifier = nil
      expect { verifier = build }.to output.to_stderr

      access_token = verifier.verify_token(zone.token({ "aud" => "https://other.example.test" }))

      expect(access_token.audiences).to eq(["https://other.example.test"])
    end
  end

  describe "construction with audiences" do
    it "emits nothing for a string" do
      expect { build(audiences: "https://api.acme.test") }.not_to output.to_stderr
    end

    it "emits nothing for an array" do
      expect { build(audiences: ["https://api.acme.test", "https://api.acme.test/mcp"]) }.not_to output.to_stderr
    end

    it "rejects a token minted for another resource" do
      verifier = build(audiences: "https://api.acme.test")

      expect { verifier.verify_token(zone.token({ "aud" => "https://other.example.test" })) }
        .to raise_error(Keycardai::OAuth::InvalidTokenError)
    end
  end
end
