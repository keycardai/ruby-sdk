# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/oauth-client/token-exchange.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::TokenExchangeClient do
  let(:zone) { ZoneFixture.new }
  let(:token_payload) do
    { "access_token" => "at_new", "token_type" => "Bearer", "expires_in" => 300,
      "scope" => "read write", "issued_token_type" => Keycardai::OAuth::TokenType::ACCESS_TOKEN }
  end

  def token_http(payload = token_payload, status: 200)
    FakeHTTPClient.new do |url, _params|
      url == zone.metadata_url ? json_response(zone.metadata) : json_response(payload, status: status)
    end
  end

  def client(http, **options)
    described_class.new(issuer: zone.issuer, http_client: http, **options)
  end

  def token_call(http)
    http.calls.find { |call| call.url == zone.token_url }
  end

  def request(subject)
    subject.exchange_token(subject_token: "at_subject")
  end

  include_examples "token-endpoint discovery is not sticky", %w[8 9 10 11 12 13]

  it "1: defaults grant_type to token-exchange and subject_token_type to access-token" do
    http = token_http
    client(http).exchange_token(subject_token: "at_subject")

    expect(token_call(http).params).to include(
      "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
      "subject_token" => "at_subject",
      "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token"
    )
  end

  it "2: form-encodes resource, scope, and actor_token/actor_token_type when set" do
    http = token_http
    client(http).exchange_token(
      subject_token: "at_subject", resource: "https://api.acme.test", scope: "read",
      actor_token: "at_actor", actor_token_type: Keycardai::OAuth::TokenType::ACCESS_TOKEN
    )

    expect(token_call(http).params).to include(
      "resource" => "https://api.acme.test",
      "scope" => "read",
      "actor_token" => "at_actor",
      "actor_token_type" => "urn:ietf:params:oauth:token-type:access_token"
    )
  end

  it "3: a shared-secret client sends an HTTP Basic Authorization header" do
    http = token_http
    client(http, client_id: "cid", client_secret: "csecret").exchange_token(subject_token: "at_subject")

    expect(token_call(http).headers["Authorization"]).to eq("Basic #{["cid:csecret"].pack("m0")}")
    expect(token_call(http).params).not_to have_key("client_id")
  end

  it "4: client_assertion fields are form-encoded with no Basic header when no secret is configured" do
    http = token_http
    client(http).exchange_token(
      subject_token: "at_subject",
      client_assertion: "assertion-jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )

    call = token_call(http)
    expect(call.params).to include(
      "client_assertion" => "assertion-jwt",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    expect(call.headers).not_to have_key("Authorization")
  end

  it "4a: client_assertion, client_assertion_type, and client_id are form-encoded with no Basic header" do
    http = token_http
    client(http).exchange_token(
      subject_token: "at_subject",
      client_assertion: "assertion-jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_id: "app_123"
    )

    call = token_call(http)
    expect(call.params).to include(
      "client_assertion" => "assertion-jwt",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_id" => "app_123"
    )
    expect(call.headers).not_to have_key("Authorization")
  end

  it "4b: sends prepared authentication and retains the caller's other fields" do
    http = token_http
    resource = "https://api.acme.test"
    credential = instance_double(Keycardai::OAuth::WorkloadIdentity, authorization_header: nil)
    expect(credential).to receive(:prepare_token_exchange_request).with(
      subject_token: "at_subject", resource: resource, token_endpoint: zone.token_url, issuer: zone.issuer
    ).and_return(
      "subject_token" => "ignored", "scope" => "ignored", "resource" => "ignored",
      "client_assertion" => "prepared-jwt", "client_assertion_type" => Keycardai::OAuth::PrivateKeyManager::ASSERTION_TYPE,
      "client_id" => "prepared-client"
    )

    client(http, credential: credential).exchange_token(subject_token: "at_subject", resource: resource, scope: "read")

    expect(token_call(http).params).to include(
      "subject_token" => "at_subject", "scope" => "read", "resource" => resource,
      "client_assertion" => "prepared-jwt", "client_assertion_type" => Keycardai::OAuth::PrivateKeyManager::ASSERTION_TYPE,
      "client_id" => "prepared-client"
    )
    expect(token_call(http).headers).not_to have_key("Authorization")
  end

  it "4c: sends caller authentication without preparing an assertion" do
    http = token_http
    credential = instance_double(Keycardai::OAuth::WorkloadIdentity, authorization_header: nil)
    expect(credential).not_to receive(:prepare_token_exchange_request)
    assertion_type = Keycardai::OAuth::PrivateKeyManager::ASSERTION_TYPE

    client(http, credential: credential).exchange_token(
      subject_token: "at_subject", client_assertion: "caller-jwt",
      client_assertion_type: assertion_type, client_id: "caller-client"
    )

    expect(token_call(http).params).to include(
      "client_assertion" => "caller-jwt", "client_assertion_type" => assertion_type, "client_id" => "caller-client"
    )
    expect(token_call(http).headers).not_to have_key("Authorization")
  end

  it "4d: surfaces the identity source failure without a token POST" do
    http = token_http
    credential = Keycardai::OAuth::WorkloadIdentity.new(source: -> { raise "metadata down" })

    expect { request(client(http, credential: credential)) }
      .to raise_error(Keycardai::OAuth::WorkloadIdentityRuntimeError, /metadata down/)
    expect(token_call(http)).to be_nil
  end

  ["prepared-client", nil].each do |prepared_id|
    it "4e: uses only the prepared client ID (#{prepared_id.inspect})" do
      http = token_http
      credential = Keycardai::OAuth::WorkloadIdentity.new(source: -> { "prepared-jwt" }, client_id: prepared_id)

      client(http, credential: credential).exchange_token(subject_token: "at_subject", client_id: "caller-client")

      expect(token_call(http).params.fetch("client_id", nil)).to eq(prepared_id)
      expect(token_call(http).params.key?("client_id")).to eq(!prepared_id.nil?)
    end
  end

  it "4f: rejects a request client_id with Basic before discovery and without calling actor" do
    http = token_http
    actor_calls = 0
    actor = lambda {
      actor_calls += 1
      "actor-jwt"
    }
    exchange = client(http, client_id: "configured", client_secret: "secret", actor: actor)

    expect { exchange.exchange_token(subject_token: "at_subject", client_id: "request-id") }
      .to raise_error(Keycardai::OAuth::ConfigurationError, /client_id.*HTTP Basic/)
    expect(http.calls).to be_empty
    expect(actor_calls).to eq(0)
  end

  [nil, "request-id"].each do |client_id|
    it "4g: an explicit assertion suppresses Basic with client_id #{client_id.inspect}" do
      http = token_http
      credential = Keycardai::OAuth::ClientSecret.new("configured", "secret")
      expect(credential).not_to receive(:prepare_token_exchange_request)
      assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

      client(http, credential: credential).exchange_token(
        subject_token: "at_subject", client_assertion: "assertion",
        client_assertion_type: assertion_type, client_id: client_id
      )

      call = token_call(http)
      expect(call.params).to include("client_assertion" => "assertion", "client_assertion_type" => assertion_type)
      expect(call.params["client_id"]).to eq(client_id)
      expect(call.params.key?("client_id")).to eq(!client_id.nil?)
      expect(call.headers).not_to have_key("Authorization")
    end
  end

  it "4c: a workload identity credential adds no client_id to a request carrying its own assertion" do
    http = token_http
    source = -> { raise "the configured assertion source should not be called" }
    credential = Keycardai::OAuth::WorkloadIdentity.new(source: source, client_id: "configured")
    assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    client(http, credential: credential).exchange_token(
      subject_token: "at_subject", client_assertion: "assertion", client_assertion_type: assertion_type
    )

    call = token_call(http)
    expect(call.params).to include("client_assertion" => "assertion", "client_assertion_type" => assertion_type)
    expect(call.params).not_to have_key("client_id")
    expect(call.headers).not_to have_key("Authorization")
  end

  it "5: parses a 2xx response into the token result" do
    response = client(token_http).exchange_token(subject_token: "at_subject")

    expect(response).to have_attributes(
      access_token: "at_new", token_type: "Bearer", expires_in: 300,
      scope: %w[read write], issued_token_type: Keycardai::OAuth::TokenType::ACCESS_TOKEN
    )
  end

  it "6: surfaces an OAuth error response as a typed error with its fields" do
    http = token_http({ "error" => "invalid_target", "error_description" => "unknown resource" }, status: 400)

    expect { client(http).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.error).to eq("invalid_target")
        expect(e.error_description).to eq("unknown resource")
        expect(e.status).to eq(400)
      }
  end

  it "6a: preserves the denial reason separately from the description" do
    http = token_http({ "error" => "access_denied", "error_description" => "Denied", "reason" => "custom_denial" },
                      status: 400)

    expect { client(http).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.reason).to eq("custom_denial")
        expect(e.error_description).to eq("Denied")
        expect(e).not_to be_retryable
      }
  end

  it "6b: leaves an omitted reason nil without changing retryability" do
    http = token_http({ "error" => "access_denied", "error_description" => "Denied" }, status: 400)

    expect { client(http).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.reason).to be_nil
        expect(e.error_description).to eq("Denied")
        expect(e).not_to be_retryable
      }
  end

  it "7: rejects a token response missing access_token" do
    http = token_http({ "token_type" => "Bearer" })

    expect { client(http).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("invalid_response") }
  end

  it "23: calls the actor source on every exchange and sends actor_token with JWT type" do
    http = token_http
    calls = 0
    tokens = %w[actor-jwt-1 actor-jwt-2]
    source = Class.new do
      define_method(:identity_token) do
        calls += 1
        tokens.shift
      end
    end.new

    exchange = client(http, actor: source)
    exchange.exchange_token(subject_token: "at_subject_1")
    exchange.exchange_token(subject_token: "at_subject_2")

    token_calls = http.calls.select { |call| call.url == zone.token_url }
    expect(calls).to eq(2)
    expect(token_calls.map(&:params)).to match([
                                                 include(
                                                   "actor_token" => "actor-jwt-1",
                                                   "actor_token_type" => "urn:ietf:params:oauth:token-type:jwt"
                                                 ),
                                                 include(
                                                   "actor_token" => "actor-jwt-2",
                                                   "actor_token_type" => "urn:ietf:params:oauth:token-type:jwt"
                                                 )
                                               ])
  end

  it "24: sends request actor_token and actor_token_type unchanged without calling the actor source" do
    http = token_http
    calls = 0
    actor = lambda {
      calls += 1
      "source-actor"
    }

    client(http, actor: actor).exchange_token(
      subject_token: "at_subject",
      actor_token: "request-actor",
      actor_token_type: Keycardai::OAuth::TokenType::ACCESS_TOKEN
    )

    expect(calls).to eq(0)
    expect(token_call(http).params).to include(
      "actor_token" => "request-actor",
      "actor_token_type" => "urn:ietf:params:oauth:token-type:access_token"
    )
  end

  it "25: impersonate sends no actor_token fields and does not call the actor source" do
    http = token_http
    calls = 0
    actor = lambda {
      calls += 1
      "source-actor"
    }

    client(http, actor: actor).impersonate(user_identifier: "usr_123", resource: "https://api.acme.test")

    expect(calls).to eq(0)
    expect(token_call(http).params).not_to have_key("actor_token")
    expect(token_call(http).params).not_to have_key("actor_token_type")
  end

  it "26: surfaces actor source failures as typed errors without making any HTTP request" do
    config_error = Keycardai::OAuth::WorkloadIdentityConfigurationError.new("missing file", source: "file")
    config_http = token_http
    expect { client(config_http, actor: -> { raise config_error }).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::WorkloadIdentityConfigurationError) { |e|
        expect(e).to equal(config_error)
        expect(e.source).to eq("file")
        expect(e).not_to be_retryable
      }
    expect(config_http.calls).to be_empty

    runtime_error = Keycardai::OAuth::WorkloadIdentityRuntimeError.new(
      "metadata down", source: "gcp-metadata", retryable: true
    )
    runtime_http = token_http
    expect { client(runtime_http, actor: -> { raise runtime_error }).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::WorkloadIdentityRuntimeError) { |e|
        expect(e).to equal(runtime_error)
        expect(e.source).to eq("gcp-metadata")
        expect(e).to be_retryable
      }
    expect(runtime_http.calls).to be_empty

    plain_http = token_http
    plain_client = client(plain_http, actor: -> { raise IOError, "socket closed" })
    expect { plain_client.exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::WorkloadIdentityRuntimeError) { |e|
        expect(e.source).to eq("custom")
        expect(e.cause).to be_a(IOError)
        expect(e.cause.message).to eq("socket closed")
        expect(e).not_to be_retryable
      }
    expect(plain_http.calls).to be_empty
  end

  it "discovers the token endpoint once and caches it across calls" do
    http = token_http
    exchange = client(http)
    exchange.exchange_token(subject_token: "at_1")
    exchange.exchange_token(subject_token: "at_2")

    expect(http.request_count(zone.metadata_url)).to eq(1)
    expect(http.request_count(zone.token_url)).to eq(2)
  end

  it "requires actor_token_type when actor_token is set" do
    expect { client(token_http).exchange_token(subject_token: "at", actor_token: "at_actor") }
      .to raise_error(ArgumentError, /actor_token_type/)
  end

  it "requires client_assertion_type when client_assertion is set" do
    http = token_http
    expect { client(http).exchange_token(subject_token: "at", client_assertion: "jwt") }
      .to raise_error(ArgumentError, /client_assertion_type/)
    expect(http.request_count(zone.token_url)).to eq(0)
  end

  it "requires client_id and client_secret together" do
    expect { client(token_http, client_id: "cid") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "rejects an actor that responds to neither identity_token nor call" do
    expect { client(token_http, actor: "not-a-source") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end

  it "wraps an empty token from the actor source without making any HTTP request" do
    http = token_http
    expect { client(http, actor: -> { "" }).exchange_token(subject_token: "at_subject") }
      .to raise_error(Keycardai::OAuth::WorkloadIdentityRuntimeError) { |e|
        expect(e.source).to eq("custom")
        expect(e).not_to be_retryable
      }
    expect(http.calls).to be_empty
  end

  it "sends the actor token alongside an explicit client_assertion" do
    http = token_http
    client(http, actor: -> { "actor-jwt" }).exchange_token(
      subject_token: "at_subject",
      client_assertion: "assertion-jwt",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )

    expect(token_call(http).params).to include(
      "client_assertion" => "assertion-jwt",
      "actor_token" => "actor-jwt",
      "actor_token_type" => "urn:ietf:params:oauth:token-type:jwt"
    )
  end
end
