# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/application-credentials/client-secret.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::ClientSecret do
  it "1: a single-zone credential yields the Basic authorization header" do
    credential = described_class.new("cid", "csecret")

    expect(credential.authorization_header).to eq("Basic #{["cid:csecret"].pack("m0")}")
    expect(credential.multi_zone?).to be(false)
  end

  it "2: an empty client_id or client_secret is a configuration error at construction" do
    expect { described_class.new("", "csecret") }.to raise_error(Keycardai::OAuth::ConfigurationError)
    expect { described_class.new("cid", "") }.to raise_error(Keycardai::OAuth::ConfigurationError)
    expect { described_class.new("cid", nil) }.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "3: a multi-zone credential resolves the configured zone's Basic header" do
    credential = described_class.new(
      "https://acme.test" => %w[cid_a secret_a],
      "https://beta.test" => %w[cid_b secret_b]
    )

    expect(credential.authorization_header(issuer: "https://beta.test"))
      .to eq("Basic #{["cid_b:secret_b"].pack("m0")}")
    expect(credential.authorization_header(issuer: "https://beta.test/"))
      .to eq("Basic #{["cid_b:secret_b"].pack("m0")}")
    expect(credential.issuers).to contain_exactly("https://acme.test", "https://beta.test")
  end

  it "4: an operation for an unconfigured zone fails closed with no fallback" do
    credential = described_class.new("https://acme.test" => %w[cid_a secret_a])

    expect { credential.authorization_header(issuer: "https://unknown.test") }
      .to raise_error(Keycardai::OAuth::ConfigurationError) { |e|
        expect(e.message).not_to include("secret_a")
      }
    expect { credential.authorization_header }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "5: an empty multi-zone map is a configuration error at construction" do
    expect { described_class.new({}) }.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "6: the prepared token-exchange request uses the access-token type with no body credentials" do
    params = described_class.new("cid", "csecret").prepare_token_exchange_request(
      subject_token: "at_subject", resource: "https://api.acme.test"
    )

    expect(params).to include(
      "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
      "subject_token" => "at_subject",
      "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token",
      "resource" => "https://api.acme.test"
    )
    expect(params.keys).not_to include("client_id", "client_secret", "client_assertion")
  end
end
