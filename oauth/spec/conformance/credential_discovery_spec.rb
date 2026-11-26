# frozen_string_literal: true

require "tmpdir"

# Unit Tests for keycard-sdk-spec specs/application-credentials/credential-discovery.md v3.
RSpec.describe "Application credential discovery" do
  let(:client_env) { { "KEYCARD_CLIENT_ID" => "cid", "KEYCARD_CLIENT_SECRET" => "client-secret" } }
  let(:token_env) { { "AWS_WEB_IDENTITY_TOKEN_FILE" => token_file } }
  let(:storage_dir) { File.join(@temp_dir, "keys") }
  let(:web_env) { { "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR" => storage_dir } }
  let(:selector) { "KEYCARD_APPLICATION_CREDENTIAL_TYPE" }
  let(:token_file) { write_token_file("first-token") }
  let(:discovery_error) { Keycardai::OAuth::CredentialDiscoveryError }
  let(:token_vars) do
    %w[
      KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE
      AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
      AWS_WEB_IDENTITY_TOKEN_FILE
      AZURE_FEDERATED_TOKEN_FILE
    ]
  end

  around do |example|
    Dir.mktmpdir do |dir|
      @temp_dir = dir
      example.run
    end
  end

  def discover(env, **options)
    Keycardai::OAuth.discover_application_credential(env: env, **options)
  end

  def write_token_file(contents)
    path = File.join(@temp_dir, contents.empty? ? "empty" : contents)
    File.write(path, contents)
    path
  end

  def assertion(credential)
    credential.prepare_token_exchange_request(subject_token: "subject").fetch("client_assertion")
  end

  def expect_discovery_error(env, reason, resolvable, message = nil)
    expect { discover(env) }.to raise_error(discovery_error, message) do |error|
      expect(error.reason).to eq(reason)
      expect(error.resolvable).to eq(resolvable)
    end
  end

  def with_process_env(values)
    names = [*client_env.keys, *token_vars, *web_env.keys, selector]
    saved = names.to_h { |name| [name, ENV.fetch(name, nil)] }
    ENV.update(names.to_h { |name| [name, values[name]] })
    yield
  ensure
    ENV.update(saved)
  end

  it "1: builds a ClientSecret with the discovered id and secret" do
    with_process_env(client_env) do
      credential = Keycardai::OAuth.discover_application_credential
      expect(credential).to be_a(Keycardai::OAuth::ClientSecret)
      expect(credential.authorization_header).to eq("Basic Y2lkOmNsaWVudC1zZWNyZXQ=")
    end
  end

  it "2: reads the token file named by each supported variable without attaching a client id" do
    expect(Keycardai::OAuth::FileTokenSource).to receive(:new).exactly(token_vars.size).times.and_call_original
    token_vars.each do |name|
      credential = discover({ name => token_file })
      expect(credential).to be_a(Keycardai::OAuth::WorkloadIdentity)
      expect(credential.client_id).to be_nil
      expect(assertion(credential)).to eq("first-token")
    end
  end

  it "3: raises the typed absent configuration error for an empty environment" do
    expect(discovery_error).to be < Keycardai::OAuth::ConfigurationError
    expect_discovery_error({}, :absent, [], /No application credential/)
  end

  it "4: rejects a secret without an id as incomplete" do
    expect_discovery_error({ "KEYCARD_CLIENT_SECRET" => "client-secret" }, :incomplete, [],
                           /KEYCARD_CLIENT_SECRET is set without KEYCARD_CLIENT_ID/)
  end

  it "5: names both resolvable types and the selector when a client secret and token file are configured" do
    expect_discovery_error(client_env.merge(token_env), :ambiguous, %w[client_secret workload_identity],
                           /client_secret and workload_identity.*#{selector}/)
  end

  it "6: builds exactly the selected type, including the deprecated workload identity alias" do
    env = client_env.merge(token_env, web_env)
    expect(discover(env.merge(selector => "client_secret"))).to be_a(Keycardai::OAuth::ClientSecret)
    %w[workload_identity eks_workload_identity].each do |type|
      credential = discover(env.merge(selector => type))
      expect(credential).to be_a(Keycardai::OAuth::WorkloadIdentity)
      expect(credential.client_id).to eq("cid")
      expect(assertion(credential)).to eq("first-token")
    end
    expect(discover(env.merge(selector => "web_identity"))).to be_a(Keycardai::OAuth::WebIdentity)
  end

  it "7: reports an unknown selector and lists all three canonical values" do
    expect_discovery_error({ selector => "other" }, :unknown_type, [],
                           /#{selector}.*\bclient_secret, workload_identity, web_identity\b/)
  end

  it "8: rejects an unknown selector even when a client secret resolves" do
    expect_discovery_error(client_env.merge(selector => "other"), :unknown_type, ["client_secret"])
  end

  it "9: rejects an explicit client secret selection without the secret" do
    env = { selector => "client_secret", "KEYCARD_CLIENT_ID" => "cid" }
    expect_discovery_error(env, :not_satisfiable, [], /KEYCARD_CLIENT_ID and KEYCARD_CLIENT_SECRET/)
  end

  it "10: rejects an explicit workload identity selection without a token file variable" do
    expect_discovery_error({ selector => "workload_identity" }, :not_satisfiable, [], /token file path/)
  end

  it "11: attaches a standalone client id to a workload identity credential" do
    credential = discover(token_env.merge("KEYCARD_CLIENT_ID" => "workload-client"))
    expect(credential).to be_a(Keycardai::OAuth::WorkloadIdentity)
    expect(credential.client_id).to eq("workload-client")
  end

  it "12: treats a standalone client id as absent without a token file" do
    expect_discovery_error({ "KEYCARD_CLIENT_ID" => "cid" }, :absent, [])
  end

  it "13: uses the first variable in discovery order under the legacy selector" do
    paths = token_vars.reverse.to_h { |name| [name, write_token_file(name)] }
    expect(assertion(discover(paths.merge(selector => "eks_workload_identity")))).to eq(token_vars.first)
  end

  it "14: propagates the workload identity configuration error for a missing token file" do
    env = { "AWS_WEB_IDENTITY_TOKEN_FILE" => File.join(@temp_dir, "missing") }
    expect { discover(env) }.to raise_error(Keycardai::OAuth::WorkloadIdentityConfigurationError) do |error|
      expect(error.source).to eq("file")
      expect(error.message).to include("missing or empty")
    end
  end

  it "15: uses the explicit environment instead of different process values" do
    with_process_env(client_env.merge(selector => "web_identity")) do
      env = { "KEYCARD_CLIENT_ID" => "map-client", "KEYCARD_CLIENT_SECRET" => "map-secret" }
      credential = discover(env)
      expect(credential).to be_a(Keycardai::OAuth::ClientSecret)
      expect(credential.authorization_header).to eq("Basic bWFwLWNsaWVudDptYXAtc2VjcmV0")
    end
  end

  it "16: builds a WebIdentity with the supplied server name and storage directory" do
    credential = discover(web_env, web_identity_server_name: "svc")
    expect(credential).to be_a(Keycardai::OAuth::WebIdentity)
    expect(credential.key_id).to eq("svc")
    credential.public_jwks
    expect(File).to exist(File.join(storage_dir, "svc.pem"))
  end

  it "17: lets WebIdentity choose its default key name when a server name is absent" do
    credential = discover(web_env)
    expect(credential).to be_a(Keycardai::OAuth::WebIdentity)
    expect(credential.key_id).to match(/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/)
  end

  it "18: names a client secret and web identity as ambiguous" do
    expect_discovery_error(client_env.merge(web_env), :ambiguous, %w[client_secret web_identity],
                           /client_secret and web_identity.*#{selector}/)
  end

  it "19: names workload identity and web identity as ambiguous" do
    expect_discovery_error(token_env.merge(web_env), :ambiguous, %w[workload_identity web_identity],
                           /workload_identity and web_identity.*#{selector}/)
  end

  it "20: uses the default WebIdentity storage directory when explicitly selected without one" do
    Dir.chdir(@temp_dir) do
      credential = discover({ selector => "web_identity" }, web_identity_server_name: "svc")
      expect(credential).to be_a(Keycardai::OAuth::WebIdentity)
      credential.public_jwks
      expect(File).to exist("./server_keys/svc.pem")
    end
  end

  it "21: uses the explicit WebIdentity directory without reading a process client secret" do
    with_process_env(client_env) do
      credential = discover(web_env, web_identity_server_name: "svc")
      expect(credential).to be_a(Keycardai::OAuth::WebIdentity)
      credential.public_jwks
      expect(File).to exist(File.join(storage_dir, "svc.pem"))
    end
  end

  it "22: reports absent for an empty explicit mapping even with a configured process environment" do
    with_process_env(client_env) { expect_discovery_error({}, :absent, []) }
  end

  it "23: attaches the client id to inferred and explicitly selected WebIdentity credentials" do
    Dir.chdir(@temp_dir) do
      [web_env, { selector => "web_identity" }].each do |selection|
        credential = discover(selection.merge("KEYCARD_CLIENT_ID" => "web-client"))
        expect(credential).to be_a(Keycardai::OAuth::WebIdentity)
        auth = credential.client_authentication(issuer: nil, endpoint: "https://example.test/token")
        claims, = JWT.decode(auth.params.fetch("client_assertion"), nil, false)
        expect(claims).to include("iss" => "web-client", "sub" => "web-client")
      end
    end
  end

  it "24: discovers inferred and explicitly selected WebIdentity credentials with an unset or empty id" do
    [web_env, { selector => "web_identity" }].product([{}, { "KEYCARD_CLIENT_ID" => "" }]).each do |selection, id|
      credential = discover(selection.merge(id))
      expect(credential).to be_a(Keycardai::OAuth::WebIdentity)
      expect { credential.check_client_authentication }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /requires a client_id/)
    end
  end

  it "treats empty credential variables and the selector as unset and ignores the zone URL" do
    env = [*client_env.keys, *token_vars, *web_env.keys, selector].to_h { |name| [name, ""] }
    expect_discovery_error(env.merge("KEYCARD_ZONE_URL" => "https://zone.example"), :absent, [])
    env.merge!(token_env)
    credential = discover(env)
    expect(credential.client_id).to be_nil
    expect(assertion(credential)).to eq("first-token")
  end

  it "checks a dangling secret before inference but ignores it under an explicit workload selector" do
    env = token_env.merge("KEYCARD_CLIENT_SECRET" => "dangling")
    expect_discovery_error(env, :incomplete, ["workload_identity"])
    expect(assertion(discover(env.merge(selector => "workload_identity")))).to eq("first-token")
  end

  it "does not fall back to a lower priority file if the first non-empty path names an empty file" do
    env = token_env.merge(token_vars.first => write_token_file(""))
    expect { discover(env) }.to raise_error(Keycardai::OAuth::WorkloadIdentityConfigurationError, /missing or empty/)
  end

  it "does not validate an unselected token file" do
    env = client_env.merge(selector => "client_secret", token_vars.first => File.join(@temp_dir, "missing"))
    expect(discover(env)).to be_a(Keycardai::OAuth::ClientSecret)
  end
end
