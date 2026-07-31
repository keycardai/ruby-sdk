# frozen_string_literal: true

RSpec.describe Keycardai::OAuth do
  it "has a version number" do
    expect(Keycardai::OAuth::VERSION).not_to be_nil
  end

  it "roots the error taxonomy at Keycardai::Error" do
    expect(Keycardai::Error.ancestors).to include(StandardError)
  end
end
