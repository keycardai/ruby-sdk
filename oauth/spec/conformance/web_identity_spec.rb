# frozen_string_literal: true

require "tmpdir"

# Conformance suite for keycard-sdk-spec specs/application-credentials/web-identity.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::WebIdentity do
  around do |example|
    Dir.mktmpdir { |dir| @storage_dir = dir and example.run }
  end

  let(:token_endpoint) { "https://acme.test/oauth/token" }

  def credential(**options)
    defaults = { client_id: "client_abc", key_id: "test-key", storage_dir: @storage_dir }
    described_class.new(**defaults, **options)
  end

  it "1: generates and persists a keypair on first use; a later use loads the same keypair" do
    first = credential.prepare_token_exchange_request(subject_token: "at", token_endpoint: token_endpoint)
    second = credential.prepare_token_exchange_request(subject_token: "at", token_endpoint: token_endpoint)

    first_key = decode_jwt_part(first.fetch("client_assertion").split(".")[0])
    second_key = decode_jwt_part(second.fetch("client_assertion").split(".")[0])
    expect(File).to exist(File.join(@storage_dir, "test-key.pem"))
    expect(first_key["kid"]).to eq("test-key")
    expect(second_key["kid"]).to eq("test-key")
    expect(credential.public_jwks).to eq(credential.public_jwks)
  end

  it "2: key-id resolution prefers explicit key_id, then sanitized server_name, then a generated id" do
    expect(credential(key_id: "explicit", server_name: "My Server").key_id).to eq("explicit")
    expect(credential(key_id: nil, server_name: "My Server v2!").key_id).to eq("my-server-v2")
    expect(credential(key_id: nil, server_name: nil).key_id).not_to be_empty
  end

  it "3: the prepared token-exchange request carries a jwt-bearer assertion and no Basic credentials" do
    params = credential.prepare_token_exchange_request(subject_token: "at", token_endpoint: token_endpoint)

    expect(params).to include(
      "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    expect(params.fetch("client_assertion")).not_to be_empty
    expect(params.keys).not_to include("client_secret")
  end

  it "4: the signed assertion carries iss = sub = client_id, aud = token_endpoint, jti, iat, exp = iat + 300" do
    now = Time.at(1_753_920_000)
    params = credential(clock: -> { now }).prepare_token_exchange_request(
      subject_token: "at", token_endpoint: token_endpoint
    )

    header, claims = params.fetch("client_assertion").split(".").first(2).map { |part| decode_jwt_part(part) }
    expect(header).to include("alg" => "RS256", "kid" => "test-key")
    expect(claims).to include(
      "iss" => "client_abc", "sub" => "client_abc", "aud" => token_endpoint,
      "iat" => now.to_i, "exp" => now.to_i + 300
    )
    expect(claims.fetch("jti")).not_to be_empty
  end

  it "5: the auth accessor yields no Basic credentials" do
    expect(credential.authorization_header).to be_nil
  end

  it "6: the public JWKS accessor yields a key set containing the signing key" do
    subject = credential
    params = subject.prepare_token_exchange_request(subject_token: "at", token_endpoint: token_endpoint)
    jwks = subject.public_jwks

    key = jwks.fetch("keys").find { |candidate| candidate["kid"] == "test-key" }
    expect(key).to include("kty" => "RSA", "use" => "sig", "alg" => "RS256")

    verify_key = JWT::JWK.import(key.transform_keys(&:to_sym)).verify_key
    assertion = params.fetch("client_assertion")
    signing_input = assertion.split(".").first(2).join(".")
    signature = assertion.split(".")[2].tr("-_", "+/")
    signature += "=" * ((4 - (signature.length % 4)) % 4)
    expect(verify_key.verify(OpenSSL::Digest.new("SHA256"), signature.unpack1("m0"), signing_input)).to be(true)
    expect(subject.client_jwks_url("https://tool.example.com/")).to eq("https://tool.example.com/.well-known/jwks.json")
  end

  it "requires a client_id at construction" do
    expect { credential(client_id: nil) }.to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "requires the token_endpoint when preparing a request" do
    expect { credential.prepare_token_exchange_request(subject_token: "at") }
      .to raise_error(Keycardai::OAuth::ConfigurationError, /token_endpoint/)
  end
end
