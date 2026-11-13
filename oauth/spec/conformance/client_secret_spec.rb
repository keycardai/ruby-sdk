# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/application-credentials/client-secret.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::ClientSecret do
  it "1: a single-zone credential returns the Basic authorization header" do
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

  [
    { name: "single-zone", credential: -> { described_class.new("cid", "csecret") },
      issuer: "https://acme.test", basic: "cid:csecret" },
    { name: "multi-zone, a configured zone",
      credential: lambda {
        described_class.new("https://acme.test" => %w[cid_a secret_a], "https://beta.test" => %w[cid_b secret_b])
      },
      issuer: "https://beta.test", basic: "cid_b:secret_b" },
    { name: "multi-zone, a configured zone with a trailing slash",
      credential: lambda {
        described_class.new("https://acme.test" => %w[cid_a secret_a], "https://beta.test" => %w[cid_b secret_b])
      },
      issuer: "https://beta.test/", basic: "cid_b:secret_b" }
  ].each do |example|
    it "7: client authentication, #{example[:name]}, returns that zone's Basic header and no form fields" do
      auth = instance_exec(&example[:credential])
             .client_authentication(issuer: example[:issuer], endpoint: "#{example[:issuer]}/oauth/token")

      expect(auth).to eq(Keycardai::OAuth::ClientAuthentication.new(
                           headers: { "Authorization" => "Basic #{[example[:basic]].pack("m0")}" }, params: {}
                         ))
    end
  end

  [
    { issuer: "https://unknown.test", message: "no credentials configured for zone https://unknown.test" },
    { issuer: nil, message: "multi-zone ClientSecret requires an issuer to resolve credentials" }
  ].each do |example|
    it "7: multi-zone client authentication for issuer #{example[:issuer].inspect} fails closed" do
      credential = described_class.new("https://acme.test" => %w[cid_a secret_a])

      expect { credential.client_authentication(issuer: example[:issuer], endpoint: "https://acme.test/oauth/token") }
        .to raise_error(Keycardai::OAuth::ConfigurationError, example[:message])
    end
  end

  describe "8: HTTP Basic percent-encodes the client_id and client_secret (spec-version 3)" do
    let(:zone) { ZoneFixture.new }
    # base64("ua%3Aclient:a%20b%2B%2541"), written out so the test does not
    # share the encoder under test.
    let(:expected) { "Basic dWElM0FjbGllbnQ6YSUyMGIlMkIlMjU0MQ==" }
    let(:http) do
      FakeHTTPClient.new do |url, _params|
        url == zone.metadata_url ? json_response(zone.metadata) : json_response({ "access_token" => "at" })
      end
    end

    def token_call_header(http)
      http.calls.find { |call| call.url == zone.token_url }.headers["Authorization"]
    end

    # Every operation that sends a raw client_id and client_secret with HTTP
    # Basic. Each one returns the header it sent.
    {
      "ClientSecret#authorization_header" => lambda { |_http|
        described_class.new("ua:client", "a b+%41").authorization_header
      },
      "TokenExchangeClient" => lambda { |http|
        Keycardai::OAuth::TokenExchangeClient.new(issuer: zone.issuer, client_id: "ua:client",
                                                  client_secret: "a b+%41", http_client: http)
                                             .exchange_token(subject_token: "at_subject")
        token_call_header(http)
      },
      "ClientCredentialsClient" => lambda { |http|
        Keycardai::OAuth::ClientCredentialsClient.new(issuer: zone.issuer, client_id: "ua:client",
                                                      client_secret: "a b+%41", http_client: http)
                                                 .request_token
        token_call_header(http)
      },
      "exchange_authorization_code" => lambda { |http|
        Keycardai::OAuth.exchange_authorization_code(zone.issuer, code: "code", code_verifier: "verifier",
                                                                  redirect_uri: "http://127.0.0.1/cb",
                                                                  client_id: "ua:client", client_secret: "a b+%41",
                                                                  http_client: http)
        token_call_header(http)
      },
      "refresh_authorization" => lambda { |http|
        Keycardai::OAuth.refresh_authorization(zone.issuer, refresh_token: "rt", client_id: "ua:client",
                                                            client_secret: "a b+%41", http_client: http)
        token_call_header(http)
      }
    }.each do |name, operation|
      it "#{name} sends the encoded header" do
        expect(instance_exec(http, &operation)).to eq(expected)
      end
    end

    # Each value encodes to the exact string given, and that string decodes
    # back to the value with a percent decoder, which Keycard zones use, and
    # with an RFC 6749 Appendix B form decoder.
    [
      ["a colon", "ua:client", "ua%3Aclient"],
      ["base64 characters", "ab+/cd==", "ab%2B%2Fcd%3D%3D"],
      ["a space", "a b", "a%20b"],
      ["a literal percent escape", "%41", "%2541"],
      ["unreserved characters", "AZaz09-._~", "AZaz09-._~"],
      ["characters a form encoder may leave as they are", "!*'()", "%21%2A%27%28%29"],
      ["non-Latin-1 text", "пароль 🔑", "%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C%20%F0%9F%94%91"],
      ["an ISO-8859-1 string", "caf\xE9".dup.force_encoding(Encoding::ISO_8859_1), "caf%C3%A9"]
    ].each do |name, value, encoded|
      it "encodes #{name} and round-trips it through both decoders" do
        credentials = Keycardai::OAuth::HTTP.basic_authorization(value, value).delete_prefix("Basic ").unpack1("m0")

        expect(credentials).to eq("#{encoded}:#{encoded}")
        expect(URI.decode_uri_component(encoded)).to eq(value.encode(Encoding::UTF_8))
        expect(URI.decode_www_form_component(encoded)).to eq(value.encode(Encoding::UTF_8))
      end
    end

    it "encodes a binary string byte for byte" do
      header = Keycardai::OAuth::HTTP.basic_authorization("caf\xC3\xA9".b, "\xFF".b)
      credentials = header.delete_prefix("Basic ").unpack1("m0")

      expect(credentials).to eq("caf%C3%A9:%FF")
    end
  end
end
