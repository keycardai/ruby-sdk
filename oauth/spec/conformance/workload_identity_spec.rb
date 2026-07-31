# frozen_string_literal: true

require "socket"
require "tmpdir"

# Conformance suite for keycard-sdk-spec specs/application-credentials/workload-identity.md.
# Each example maps to a row of the spec's Unit Tests table. Row 10 (the
# deprecated EKS constructor alias) has no Ruby mapping: this SDK is new and
# ships no deprecated surface; FileTokenSource covers the EKS contract.
RSpec.describe Keycardai::OAuth::WorkloadIdentity do
  # A minimal typed source for driving the credential.
  let(:rotating_source_class) do
    Class.new do
      attr_accessor :token

      def initialize(token)
        @token = token
      end

      def identity_token
        @token
      end

      def source_identifier
        "test"
      end
    end
  end

  def prepare(credential, **options)
    credential.prepare_token_exchange_request(subject_token: "at_subject", **options)
  end

  it "1: prepares a jwt-bearer exchange with the source's token and no Basic credentials" do
    credential = described_class.new(source: rotating_source_class.new("platform-token"))

    params = prepare(credential, resource: "https://api.acme.test")

    expect(params).to include(
      "client_assertion" => "platform-token",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token"
    )
    expect(credential.authorization_header).to be_nil
  end

  it "2: does not cache; a changed source token is used on the next request" do
    source = rotating_source_class.new("token-1")
    credential = described_class.new(source: source)

    expect(prepare(credential)["client_assertion"]).to eq("token-1")
    source.token = "token-2"
    expect(prepare(credential)["client_assertion"]).to eq("token-2")
  end

  it "3: a source failure surfaces WorkloadIdentityRuntimeError with the source id and cause" do
    failing = Class.new do
      def identity_token
        raise IOError, "disk on fire"
      end
    end.new
    credential = described_class.new(source: failing)

    expect { prepare(credential) }
      .to raise_error(Keycardai::OAuth::WorkloadIdentityRuntimeError) { |e|
        expect(e.source).to eq("custom")
        expect(e.cause).to be_a(IOError)
      }
  end

  it "4: accepts a bare callable as the source" do
    credential = described_class.new(source: -> { "lambda-token" })

    expect(prepare(credential)["client_assertion"]).to eq("lambda-token")
  end

  it "4a: sends client_id as a form parameter when configured, and omits it otherwise" do
    with_id = described_class.new(source: rotating_source_class.new("t"), client_id: "app_123")
    without_id = described_class.new(source: rotating_source_class.new("t"))

    expect(prepare(with_id)).to include("client_id" => "app_123")
    expect(prepare(without_id)).not_to have_key("client_id")
  end

  describe Keycardai::OAuth::FileTokenSource do
    it "5: uses an explicit token_file_path and validates it at construction" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "token")
        File.write(path, "file-token\n")

        source = described_class.new(token_file_path: path, env: {})
        expect(source.identity_token).to eq("file-token")

        expect { described_class.new(token_file_path: File.join(dir, "missing"), env: {}) }
          .to raise_error(Keycardai::OAuth::WorkloadIdentityConfigurationError) { |e| expect(e.source).to eq("file") }
      end
    end

    it "6: discovers the path from the first set env var, env_var_name first when given" do
      Dir.mktmpdir do |dir|
        aws_path = File.join(dir, "aws-token")
        custom_path = File.join(dir, "custom-token")
        File.write(aws_path, "aws-token")
        File.write(custom_path, "custom-token")

        discovered = described_class.new(env: { "AWS_WEB_IDENTITY_TOKEN_FILE" => aws_path })
        expect(discovered.identity_token).to eq("aws-token")

        preferred = described_class.new(
          env_var_name: "MY_TOKEN_FILE",
          env: { "MY_TOKEN_FILE" => custom_path, "AWS_WEB_IDENTITY_TOKEN_FILE" => aws_path }
        )
        expect(preferred.identity_token).to eq("custom-token")
      end
    end

    it "7: no explicit path and no discovery env var is a configuration error" do
      expect { described_class.new(env: {}) }
        .to raise_error(Keycardai::OAuth::WorkloadIdentityConfigurationError) { |e| expect(e.source).to eq("file") }
    end
  end

  describe Keycardai::OAuth::GCPMetadataTokenSource do
    it "8: fetches with the identity path, audience, format=full, and Metadata-Flavor header" do
      http = FakeHTTPClient.new { |_url| Keycardai::OAuth::HTTP::Response.new(status: 200, headers: {}, body: "gcp-token") }
      source = described_class.new(audience: "https://acme.test", metadata_url: "http://metadata.test",
                                   http_client: http)

      expect(source.identity_token).to eq("gcp-token")
      call = http.calls.first
      expect(call.url).to start_with("http://metadata.test/computeMetadata/v1/instance/service-accounts/default/identity?")
      expect(call.url).to include("audience=https%3A%2F%2Facme.test", "format=full")
      expect(call.headers).to include("Metadata-Flavor" => "Google")

      failing = described_class.new(
        audience: "aud", metadata_url: "http://metadata.test",
        http_client: FakeHTTPClient.new do |_url|
          Keycardai::OAuth::HTTP::Response.new(status: 500, headers: {}, body: "")
        end
      )
      expect { failing.identity_token }
        .to raise_error(Keycardai::OAuth::WorkloadIdentityRuntimeError) { |e| expect(e.source).to eq("gcp-metadata") }
      expect { described_class.new(audience: "") }
        .to raise_error(Keycardai::OAuth::WorkloadIdentityConfigurationError)
    end
  end

  describe Keycardai::OAuth::FlyTokenSource do
    it "9: POSTs {\"aud\": audience} over the overridden Unix socket path" do
      Dir.mktmpdir do |dir|
        socket_path = File.join(dir, "fly.sock")
        received = nil
        server = UNIXServer.new(socket_path)
        server_thread = Thread.new do
          client = server.accept
          received = client.readpartial(4096)
          client.write("HTTP/1.1 200 OK\r\nContent-Type: application/jwt\r\nConnection: close\r\n\r\nfly-token")
          client.close
        end

        source = described_class.new(audience: "https://acme.test", socket_path: socket_path)
        expect(source.identity_token).to eq("fly-token")
        server_thread.join
        expect(received).to include("POST /v1/tokens/oidc HTTP/1.1")
        expect(received).to end_with(JSON.dump({ "aud" => "https://acme.test" }))
      ensure
        server&.close
      end
    end
  end
end
