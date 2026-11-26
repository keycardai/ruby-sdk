# frozen_string_literal: true

require "pp"

# keycard-sdk-spec base.md, Printed forms.
RSpec.describe Keycardai::A2A::DelegationClient do
  it "shows the issuer, the credential's class, and the protocol version, and leaves out the client secret" do
    client = described_class.new(issuer: "https://acme.test", client_id: "cid", client_secret: "cs-s3cr3t")
    shown = '#<Keycardai::A2A::DelegationClient issuer="https://acme.test", ' \
            'credential=Keycardai::OAuth::ClientSecret, protocol_version="1.0">'

    expect([client.inspect, client.to_s, client.pretty_inspect]).to eq([shown, shown, "#{shown}\n"])
  end

  it "shows only the class of a caller-supplied credential" do
    credential = Class.new do
      def self.name = "AcmeCredential"
      def inspect = "#<AcmeCredential secret=custom-secret>"
    end.new
    client = described_class.new(issuer: "https://acme.test", credential: credential, protocol_version: "0.3")
    shown = '#<Keycardai::A2A::DelegationClient issuer="https://acme.test", ' \
            'credential=AcmeCredential, protocol_version="0.3">'

    expect([client.inspect, client.to_s, client.pretty_inspect]).to eq([shown, shown, "#{shown}\n"])
  end
end
