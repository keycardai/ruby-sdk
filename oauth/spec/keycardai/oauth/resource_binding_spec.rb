# frozen_string_literal: true

RSpec.describe Keycardai::OAuth::ResourceIdentifier do
  it "parses a bare origin HTTP(S) identifier and maps empty path to / for request matching" do
    id = described_class.parse("https://api.example.com")

    expect(id.http?).to be(true)
    expect(id.urn?).to be(false)
    expect(id.raw).to eq("https://api.example.com")
    expect(id.origin).to eq("https://api.example.com")
    expect(id.metadata_path).to eq("/.well-known/oauth-protected-resource")
    expect(id.metadata_url).to eq("https://api.example.com/.well-known/oauth-protected-resource")
    expect(id.matches_request?(path: "/", query: "")).to be(true)
    expect(id.matches_request?(path: "/mcp", query: "")).to be(false)
  end

  it "preserves non-default port, path, and query verbatim" do
    id = described_class.parse("https://api.example.com:8443/app/mcp?v=1")

    expect(id.raw).to eq("https://api.example.com:8443/app/mcp?v=1")
    expect(id.origin).to eq("https://api.example.com:8443")
    expect(id.metadata_path).to eq("/.well-known/oauth-protected-resource/app/mcp")
    expect(id.metadata_url).to eq("https://api.example.com:8443/.well-known/oauth-protected-resource/app/mcp?v=1")
    expect(id.matches_request?(path: "/app/mcp", query: "v=1")).to be(true)
    expect(id.matches_request?(path: "/app/mcp", query: "")).to be(false)
    expect(id.matches_metadata_request?(path: "/.well-known/oauth-protected-resource/app/mcp", query: "v=1"))
      .to be(true)
    expect(id.matches_metadata_request?(path: "/.well-known/oauth-protected-resource/app/mcp", query: ""))
      .to be(false)
  end

  it "parses a URN without publishing discovery metadata" do
    id = described_class.parse("urn:example:service:v1")

    expect(id.urn?).to be(true)
    expect(id.http?).to be(false)
    expect(id.raw).to eq("urn:example:service:v1")
    expect(id.metadata_url).to be_nil
    expect(id.matches_request?(path: "/", query: "")).to be(false)
  end

  it "rejects relative URLs, userinfo, fragments, and non-HTTP schemes" do
    [
      "",
      "/mcp",
      "ftp://api.example.com/mcp",
      "https://user:pass@api.example.com/mcp",
      "https://api.example.com/mcp#frag",
      "https://"
    ].each do |invalid|
      expect { described_class.parse(invalid) }.to raise_error(Keycardai::OAuth::ConfigurationError)
    end
  end
end

RSpec.describe Keycardai::OAuth::ResourceBinding do
  it "derives zone issuers retaining scheme and non-default port" do
    expect(described_class.derive_zone_issuer("https://keycard.cloud", "acme"))
      .to eq("https://acme.keycard.cloud")
    expect(described_class.derive_zone_issuer("https://keycard.cloud:8443", "acme"))
      .to eq("https://acme.keycard.cloud:8443")
    expect(described_class.derive_zone_issuer("https://keycard.cloud:443", "acme"))
      .to eq("https://acme.keycard.cloud")
  end

  it "rejects invalid zone IDs and missing base issuers" do
    expect { described_class.derive_zone_issuer("https://keycard.cloud", "bad/zone") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
    expect { described_class.derive_zone_issuer(nil, "acme") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end
end
