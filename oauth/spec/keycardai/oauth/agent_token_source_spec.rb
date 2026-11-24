# frozen_string_literal: true

require "pp"

RSpec.describe Keycardai::OAuth::AgentTokenSource do
  env = { "KEYCARD_SOCKET" => "/run/env.sock", "AWS_SECRET_ACCESS_KEY" => "s3cr3t-env" }
  source = described_class.new(socket: "/run/agent.sock", env: env, workload: "digest", app_id: "urn:app:zazu",
                               org: "org_1", zone: "zone_1")
  transport = Keycardai::OAuth::ResourceTransport.new(source: source, resource: "https://api.acme.test")
  shown = '#<Keycardai::OAuth::AgentTokenSource socket="/run/agent.sock", workload="digest", ' \
          'app_id="urn:app:zazu", org="org_1", zone="zone_1">'

  [
    { name: "inspect", render: -> { source.inspect }, expected: shown },
    { name: "to_s", render: -> { source.to_s }, expected: shown },
    { name: "pp", render: -> { source.pretty_inspect }, expected: "#{shown}\n" }
  ].each do |example|
    it "#{example[:name]} shows the socket and declared fields and leaves out env" do
      expect(example[:render].call).to eq(example[:expected])
    end
  end

  # pp and inspect walk the transport's instance variables, so the source's
  # own rendering is all that keeps env out.
  [
    { name: "inspect", render: -> { transport.inspect } },
    { name: "pp", render: -> { transport.pretty_inspect } }
  ].each do |example|
    it "#{example[:name]} of a ResourceTransport holding the source leaves out env" do
      rendered = example[:render].call

      expect(rendered).to include('socket="/run/agent.sock"')
      expect(rendered).not_to include("s3cr3t-env", "/run/env.sock")
    end
  end

  it "inspect with the default env does not show the process environment" do
    expect(described_class.new.inspect).not_to include(ENV.fetch("PATH"))
  end
end
