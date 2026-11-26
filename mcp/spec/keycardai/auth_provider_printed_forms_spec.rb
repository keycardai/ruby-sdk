# frozen_string_literal: true

require "pp"

# keycard-sdk-spec base.md, Printed forms.
RSpec.describe Keycardai::MCP::AuthProvider do
  it "shows the zone URL, the audiences, and the credential's class, and leaves out the client secret" do
    provider = described_class.new(zone_url: "https://acme.test", client_id: "cid", client_secret: "cs-s3cr3t",
                                   audiences: "https://api.acme.test")
    shown = '#<Keycardai::MCP::AuthProvider zone_url="https://acme.test", audiences="https://api.acme.test", ' \
            "credential=Keycardai::OAuth::ClientSecret>"

    expect([provider.inspect, provider.to_s, provider.pretty_inspect]).to eq([shown, shown, "#{shown}\n"])
  end

  it "shows only the class of a caller-supplied credential" do
    credential = Class.new do
      def self.name = "AcmeCredential"
      def inspect = "#<AcmeCredential secret=custom-secret>"
    end.new
    provider = described_class.new(zone_url: "https://acme.test", credential: credential)
    shown = '#<Keycardai::MCP::AuthProvider zone_url="https://acme.test", audiences=nil, credential=AcmeCredential>'

    expect([provider.inspect, provider.to_s, provider.pretty_inspect]).to eq([shown, shown, "#{shown}\n"])
  end
end
