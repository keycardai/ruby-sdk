# frozen_string_literal: true

require "json"
require "pp"
require "tmpdir"

# keycard-sdk-spec base.md, Printed forms: inspect, to_s, and pp leave out
# every secret and show the other fields. #to_h and JSON keep the values.
RSpec.describe "printed forms" do
  def printed_forms(value)
    { inspect: value.inspect, to_s: value.to_s, pp: value.pretty_inspect }
  end

  def expect_printed(value, shown)
    printed_forms(value).each do |form, text|
      expected = form == :pp ? "#{shown}\n" : shown
      expect(text).to eq(expected), "#{form} printed #{text}"
    end
  end

  describe Keycardai::OAuth::TokenResponse do
    let(:payload) do
      { "access_token" => "at-s3cr3t", "token_type" => "Bearer", "expires_in" => 3600, "scope" => "read write",
        "issued_token_type" => Keycardai::OAuth::TokenType::ACCESS_TOKEN, "refresh_token" => "rt-s3cr3t",
        "id_token" => "idt-s3cr3t" }
    end
    let(:token) { described_class.from_wire(payload) }

    it "leaves out the access, refresh, and ID tokens and shows the other fields" do
      expect_printed(token, '#<data Keycardai::OAuth::TokenResponse token_type="Bearer", expires_in=3600, ' \
                            'scope=["read", "write"], ' \
                            'issued_token_type="urn:ietf:params:oauth:token-type:access_token", ' \
                            'raw=["access_token", "token_type", "expires_in", "scope", "issued_token_type", ' \
                            '"refresh_token", "id_token"]>')
    end

    it "leaves the tokens out of an object that holds the response" do
      context = Keycardai::OAuth::AccessContext.new({ "https://api.acme.test" => token })

      [context.inspect, context.pretty_inspect, [token].inspect, { r: token }.pretty_inspect].each do |text|
        expect(text).not_to include("s3cr3t")
      end
    end

    it "keeps every token in to_h, raw, and JSON" do
      expect(token.to_h.values_at(:access_token, :refresh_token, :id_token))
        .to eq(%w[at-s3cr3t rt-s3cr3t idt-s3cr3t])
      expect(token.raw).to eq(payload)
      expect(JSON.parse(JSON.generate(token.to_h))).to include(
        "access_token" => "at-s3cr3t", "refresh_token" => "rt-s3cr3t", "id_token" => "idt-s3cr3t", "raw" => payload
      )
    end
  end

  describe Keycardai::OAuth::AccessToken do
    let(:token) { described_class.new(token: "bearer-s3cr3t", claims: { "sub" => "user-1" }) }

    it "leaves out the bearer token and shows the claims" do
      expect_printed(token, "#<data Keycardai::OAuth::AccessToken claims=#{token.claims.inspect}>")
    end

    it "keeps the token" do
      expect(token.token).to eq("bearer-s3cr3t")
      expect(token.to_h[:token]).to eq("bearer-s3cr3t")
      expect(JSON.parse(token.to_json)).to include("token" => "bearer-s3cr3t")
    end
  end

  describe Keycardai::OAuth::ClientAuthentication do
    it "shows only header and form field names, and keeps the values in to_h" do
      auth = described_class.new(headers: { "Authorization" => "basic-secret" },
                                 params: { "client_assertion" => "assertion-secret", "client_id" => "cid" })

      expect_printed(auth, '#<data Keycardai::OAuth::ClientAuthentication headers=["Authorization"], ' \
                           'params=["client_assertion", "client_id"]>')
      expect(auth.to_h).to eq(headers: { "Authorization" => "basic-secret" },
                              params: { "client_assertion" => "assertion-secret", "client_id" => "cid" })
      expect(auth.to_json).not_to include("basic-secret")
      expect(auth.to_json).not_to include("assertion-secret")
    end
  end

  describe Keycardai::OAuth::ClientRegistrationResponse do
    let(:raw) do
      { "client_id" => "cid", "client_secret" => "cs-s3cr3t", "registration_access_token" => "rat-s3cr3t",
        "client_name" => "agent" }
    end
    let(:registration) do
      described_class.new(client_id: "cid", client_secret: "cs-s3cr3t", client_id_issued_at: 1_700_000_000,
                          client_secret_expires_at: 0, registration_access_token: "rat-s3cr3t",
                          registration_client_uri: "https://acme.test/register/cid", raw: raw)
    end

    it "leaves out the client secret and the registration access token" do
      expect_printed(registration,
                     '#<data Keycardai::OAuth::ClientRegistrationResponse client_id="cid", ' \
                     "client_id_issued_at=1700000000, client_secret_expires_at=0, " \
                     'registration_client_uri="https://acme.test/register/cid", ' \
                     'raw=["client_id", "client_secret", "registration_access_token", "client_name"]>')
    end

    it "keeps the values in to_h and raw" do
      expect(registration.to_h.values_at(:client_secret, :registration_access_token)).to eq(%w[cs-s3cr3t rat-s3cr3t])
      expect(registration["client_secret"]).to eq("cs-s3cr3t")
      secrets = { "client_secret" => "cs-s3cr3t", "registration_access_token" => "rat-s3cr3t" }
      expect(JSON.parse(registration.to_json)).to include(secrets)
    end
  end

  describe Keycardai::OAuth::PKCE::Pair do
    it "leaves out the code verifier and shows an S256 challenge" do
      pair = described_class.new(code_verifier: "v-s3cr3t", code_challenge: "challenge", code_challenge_method: "S256")

      expect_printed(pair, '#<data Keycardai::OAuth::PKCE::Pair code_challenge="challenge", ' \
                           'code_challenge_method="S256">')
      expect(pair.to_h[:code_verifier]).to eq("v-s3cr3t")
    end

    it "leaves out a plain challenge, which is the verifier" do
      pair = described_class.new(code_verifier: "v-s3cr3t", code_challenge: "v-s3cr3t", code_challenge_method: "plain")

      expect_printed(pair, '#<data Keycardai::OAuth::PKCE::Pair code_challenge_method="plain">')
      expect(JSON.parse(pair.to_json)).to include("code_verifier" => "v-s3cr3t", "code_challenge" => "v-s3cr3t")
    end
  end

  describe "credentials and clients" do
    # A credential defined outside the SDK, which prints its own secret.
    let(:custom_credential) do
      Class.new do
        def self.name = "AcmeCredential"
        def inspect = "#<AcmeCredential secret=\"custom-s3cr3t\">"
        def client_authentication(issuer:, endpoint:) = Keycardai::OAuth::ClientAuthentication.new
      end.new
    end
    let(:key) { OpenSSL::PKey::RSA.new(2048) }

    [
      { name: "TokenExchangeClient",
        build: ->(cred) { Keycardai::OAuth::TokenExchangeClient.new(issuer: "https://acme.test", credential: cred) },
        shown: '#<Keycardai::OAuth::TokenExchangeClient issuer="https://acme.test", credential=AcmeCredential>' },
      { name: "ClientCredentialsClient",
        build: lambda { |cred|
          Keycardai::OAuth::ClientCredentialsClient.new(issuer: "https://acme.test", credential: cred)
        },
        shown: '#<Keycardai::OAuth::ClientCredentialsClient issuer="https://acme.test", credential=AcmeCredential>' },
      { name: "DeviceAuthorizationClient",
        build: lambda { |cred|
          Keycardai::OAuth::DeviceAuthorizationClient.new(issuer: "https://acme.test", credential: cred)
        },
        shown: '#<Keycardai::OAuth::DeviceAuthorizationClient issuer="https://acme.test", client_id=nil, ' \
               "credential=AcmeCredential>" }
    ].each do |example|
      it "#{example[:name]} shows the credential's class only" do
        expect_printed(example[:build].call(custom_credential), example[:shown])
      end
    end

    it "a client built from a client_id and client_secret leaves out the secret" do
      client = Keycardai::OAuth::TokenExchangeClient.new(issuer: "https://acme.test", client_id: "cid",
                                                         client_secret: "cs-s3cr3t")

      expect_printed(client, '#<Keycardai::OAuth::TokenExchangeClient issuer="https://acme.test", ' \
                             "credential=Keycardai::OAuth::ClientSecret>")
    end

    it "JWTSigner shows the key ID and issuer" do
      signer = Keycardai::OAuth::JWTSigner.new(key: key, kid: "kid-1", issuer: "https://acme.test")

      expect_printed(signer, '#<Keycardai::OAuth::JWTSigner kid="kid-1", issuer="https://acme.test">')
    end

    it "WebIdentity and PrivateKeyManager show the client ID and key ID" do
      Dir.mktmpdir do |dir|
        identity = Keycardai::OAuth::WebIdentity.new(client_id: "cid", key_id: "kid-1", storage_dir: dir)
        identity.public_jwks
        manager = Keycardai::OAuth::PrivateKeyManager.new(
          key_id: "kid-1", storage: Keycardai::OAuth::FilePrivateKeyStorage.new(dir: dir)
        )
        manager.key

        expect_printed(identity, '#<Keycardai::OAuth::WebIdentity client_id="cid", key_id="kid-1">')
        expect_printed(manager, '#<Keycardai::OAuth::PrivateKeyManager key_id="kid-1">')
      end
    end

    it "WorkloadIdentity shows the client ID and the source's class without calling the source" do
      source = Class.new do
        def self.name = "AcmeTokenSource"
        def inspect = raise("printing inspected the source")
        def source_identifier = raise("printing called the source identifier")
        def identity_token = raise("printing called the source")
      end.new
      identity = Keycardai::OAuth::WorkloadIdentity.new(source: source, client_id: "cid")

      expect_printed(identity, '#<Keycardai::OAuth::WorkloadIdentity client_id="cid", source=AcmeTokenSource>')
    end

    it "shows the client ID of a discovered credential while keeping it usable" do
      env = { "KEYCARD_CLIENT_ID" => "cid", "KEYCARD_CLIENT_SECRET" => "cs-s3cr3t" }
      credential = Keycardai::OAuth.discover_application_credential(env: env)
      discovery = Keycardai::OAuth.const_get(:CredentialDiscovery).new(env)

      expect_printed(credential, '#<Keycardai::OAuth::ClientSecret client_id="cid">')
      shown = '#<Keycardai::OAuth::CredentialDiscovery client_id="cid", resolvable=["client_secret"]>'
      expect_printed(discovery, shown)
      expect(credential.authorization_header).to eq("Basic #{["cid:cs-s3cr3t"].pack("m0")}")
    end
  end
end
