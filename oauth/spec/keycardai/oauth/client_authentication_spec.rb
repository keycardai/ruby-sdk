# frozen_string_literal: true

require "pp"

RSpec.describe Keycardai::OAuth::ClientAuthentication do
  authentication = described_class.new(
    headers: { "Authorization" => "Basic aWQ6c2VjcmV0" },
    params: { "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              "client_assertion" => "eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl" }
  )
  shown = '#<data Keycardai::OAuth::ClientAuthentication headers=["Authorization"], ' \
          'params=["client_assertion_type", "client_assertion"]>'

  [
    { name: "inspect", render: -> { authentication.inspect }, expected: shown },
    { name: "to_s", render: -> { authentication.to_s }, expected: shown },
    { name: "pp", render: -> { authentication.pretty_inspect }, expected: "#{shown}\n" }
  ].each do |example|
    it "#{example[:name]} shows header and field names without their values" do
      expect(example[:render].call).to eq(example[:expected])
    end
  end

  it "keeps the values for the request" do
    expect(authentication.headers).to eq({ "Authorization" => "Basic aWQ6c2VjcmV0" })
    expect(authentication.params["client_assertion"]).to eq("eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl")
  end
end
