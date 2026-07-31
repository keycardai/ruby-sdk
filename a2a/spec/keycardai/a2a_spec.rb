# frozen_string_literal: true

RSpec.describe Keycardai::A2A do
  it "has a version number" do
    expect(Keycardai::A2A::VERSION).not_to be_nil
  end

  it "pins the delegation-contract constants from the a2a spec" do
    expect(Keycardai::A2A::AGENT_CARD_PATH).to eq("/.well-known/agent-card.json")
    expect(Keycardai::A2A::JSONRPC_PATH).to eq("/a2a/jsonrpc")
    expect(Keycardai::A2A::MESSAGE_SEND_METHOD).to eq("message/send")
    expect(Keycardai::A2A::PROTOCOL_VERSION).to eq("0.3")
  end
end
