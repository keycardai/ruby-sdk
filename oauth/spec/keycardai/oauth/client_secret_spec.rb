# frozen_string_literal: true

require "pp"

RSpec.describe Keycardai::OAuth::ClientSecret do
  single = described_class.new("cid", "s3cr3t-single")
  multi = described_class.new("https://acme.test" => %w[cid_a s3cr3t-a], "https://beta.test" => %w[cid_b s3cr3t-b])
  single_shown = '#<Keycardai::OAuth::ClientSecret client_id="cid">'
  multi_shown = '#<Keycardai::OAuth::ClientSecret issuers=["https://acme.test", "https://beta.test"]>'

  # The nested row checks that an object holding the credential, which pp
  # and inspect walk, does not show the secret either.
  [
    { name: "inspect of a single-zone credential", render: -> { single.inspect }, expected: single_shown },
    { name: "to_s of a single-zone credential", render: -> { single.to_s }, expected: single_shown },
    { name: "pp of a single-zone credential", render: -> { single.pretty_inspect }, expected: "#{single_shown}\n" },
    { name: "inspect of a multi-zone credential", render: -> { multi.inspect }, expected: multi_shown },
    { name: "pp of a multi-zone credential", render: -> { multi.pretty_inspect }, expected: "#{multi_shown}\n" },
    { name: "inspect of an array that holds the credential", render: -> { [single].inspect },
      expected: "[#{single_shown}]" }
  ].each do |example|
    it "#{example[:name]} leaves out the client secret" do
      expect(example[:render].call).to eq(example[:expected])
    end
  end
end
