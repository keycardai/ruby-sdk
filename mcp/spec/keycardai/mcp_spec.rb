# frozen_string_literal: true

RSpec.describe Keycardai::MCP do
  it "has a version number" do
    expect(Keycardai::MCP::VERSION).not_to be_nil
  end

  it "loads the oauth foundation gem" do
    expect(defined?(Keycardai::OAuth)).to eq("constant")
  end
end
