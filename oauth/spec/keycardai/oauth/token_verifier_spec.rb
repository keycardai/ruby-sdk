# frozen_string_literal: true

RSpec.describe Keycardai::OAuth::TokenVerifier do
  let(:zone) { ZoneFixture.new }

  def build(**options)
    described_class.new(issuers: zone.issuer, http_client: zone.http_client, **options)
  end

  describe "legacy construction without explicit mode" do
    it "warns once naming resource_identifier when audiences is omitted" do
      expect { build }
        .to output(/warning: .*deprecated.*resource_identifier/).to_stderr
    end

    it "still accepts a token minted for another resource when audiences is omitted" do
      verifier = nil
      expect { verifier = build }.to output.to_stderr

      access_token = verifier.verify_token(zone.token({ "aud" => "https://other.example.test" }))

      expect(access_token.audiences).to eq(["https://other.example.test"])
    end

    it "warns once naming resource_identifier for scalar audiences and enforces the audience" do
      verifier = nil
      expect { verifier = build(audiences: "https://api.acme.test") }
        .to output(/warning: .*deprecated.*resource_identifier/).to_stderr

      expect(verifier.verify_token(zone.token({ "aud" => "https://api.acme.test" })).audiences)
        .to eq(["https://api.acme.test"])
      expect { verifier.verify_token(zone.token({ "aud" => "https://other.example.test" })) }
        .to raise_error(Keycardai::OAuth::InvalidTokenError)
    end

    it "warns once naming resource_identifier for list audiences without multi_resource" do
      verifier = nil
      expect { verifier = build(audiences: ["https://api.acme.test", "https://api.acme.test/mcp"]) }
        .to output(/warning: .*deprecated.*resource_identifier/).to_stderr

      expect(verifier.verify_token(zone.token({ "aud" => "https://api.acme.test/mcp" })).audiences)
        .to eq(["https://api.acme.test/mcp"])
    end
  end

  describe "explicit modes" do
    it "emits no warning for single-resource HTTP(S) identifier and matches aud verbatim" do
      verifier = nil
      expect { verifier = build(resource_identifier: "https://api.acme.test") }.not_to output.to_stderr

      expect(verifier.verify_token(zone.token({ "aud" => "https://api.acme.test" })).audiences)
        .to eq(["https://api.acme.test"])
      expect { verifier.verify_token(zone.token({ "aud" => "https://api.acme.test/" })) }
        .to raise_error(Keycardai::OAuth::InvalidTokenError)
    end

    it "emits no warning for single-resource URN identifier" do
      verifier = nil
      expect { verifier = build(resource_identifier: "urn:example:service") }.not_to output.to_stderr

      expect(verifier.verify_token(zone.token({ "aud" => "urn:example:service" })).audiences)
        .to eq(["urn:example:service"])
      expect { verifier.verify_token(zone.token({ "aud" => "urn:example:other" })) }
        .to raise_error(Keycardai::OAuth::InvalidTokenError)
    end

    it "emits no warning for multi_resource with a nonempty audience list" do
      verifier = nil
      expect do
        verifier = build(multi_resource: true, audiences: ["https://api.acme.test", "https://api.acme.test/mcp"])
      end.not_to output.to_stderr

      expect(verifier.verify_token(zone.token({ "aud" => "https://api.acme.test/mcp" })).audiences)
        .to eq(["https://api.acme.test/mcp"])
    end

    it "emits no warning for allow_any_audience and skips audience check only" do
      verifier = nil
      expect { verifier = build(allow_any_audience: true) }.not_to output.to_stderr

      expect(verifier.verify_token(zone.token({ "aud" => "https://other.example.test" })).audiences)
        .to eq(["https://other.example.test"])
    end

    it "rejects invalid HTTP(S) identifiers with userinfo, fragment, or relative path" do
      expect { build(resource_identifier: "/mcp") }.to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(resource_identifier: "https://user:pass@api.example.com/mcp") }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(resource_identifier: "https://api.example.com/mcp#frag") }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(resource_identifier: "ftp://api.example.com/mcp") }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
    end

    it "rejects conflicting mode options" do
      expect { build(resource_identifier: "https://api.acme.test", allow_any_audience: true) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(resource_identifier: "https://api.acme.test", multi_resource: true) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(resource_identifier: "https://api.acme.test", audiences: "https://api.acme.test") }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(multi_resource: true, allow_any_audience: true) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(allow_any_audience: true, audiences: ["https://api.acme.test"]) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(multi_resource: true, audiences: "https://api.acme.test") }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(multi_resource: true, audiences: { "a" => "https://api.acme.test" }) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
      expect { build(multi_resource: true, audiences: []) }
        .to raise_error(Keycardai::OAuth::ConfigurationError)
    end
  end
end
