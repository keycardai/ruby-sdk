# frozen_string_literal: true

require "pp"

# keycard-sdk-spec base.md, Printed forms.
RSpec.describe Keycardai::A2A::DelegationClient do
  it "shows the issuer, the credential's class, and the protocol version, and leaves out the client secret" do
    client = described_class.new(issuer: "https://acme.test", client_id: "cid", client_secret: "cs-s3cr3t")
    shown = "#<Keycardai::A2A::DelegationClient exchange=#<Keycardai::OAuth::TokenExchangeClient " \
            'issuer="https://acme.test", credential=Keycardai::OAuth::ClientSecret>, protocol_version="1.0">'

    expect([client.inspect, client.to_s, client.pretty_inspect]).to eq([shown, shown, "#{shown}\n"])
  end
end
