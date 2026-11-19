# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec
# specs/delegated-access/local-agent-token-source.md. Each example maps to a row
# of the spec's Unit Tests or Integration Tests table. Rows 19 to 23 cover an
# SDK-side token cache, which this SDK does not keep, so they have no example.
RSpec.describe Keycardai::OAuth::AgentTokenSource do
  let(:oauth) { Keycardai::OAuth }
  let(:issue_token_path) { "/keycard.agent.v1.AgentService/IssueToken" }

  def agent_http(status: 200, payload: { "token" => "agent-token" })
    FakeHTTPClient.new do |_url, _payload|
      body = payload.is_a?(String) ? payload : JSON.dump(payload)
      Keycardai::OAuth::HTTP::Response.new(status: status, headers: {}, body: body)
    end
  end

  def source(http, **options)
    described_class.new(socket: "/unused/agent.sock", http_client: http, **options)
  end

  def mint(subject, resource: "https://api.acme.test", scopes: [])
    subject.resource_token(resource: resource, scopes: scopes)
  end

  def expect_network_error(env, message)
    message = a_string_including(message) if message.is_a?(String)
    expect { mint(described_class.new(env: env)) }.to raise_error(Keycardai::OAuth::NetworkError, message)
  end

  def error_from
    yield
    nil
  rescue StandardError => e
    e
  end

  describe "Unit Tests" do
    it "1: one IssueToken POST with the Connect headers and a body carrying resource, scopes, workload" do
      http = agent_http
      mint(source(http, workload: "digest"), scopes: %w[read write])

      expect(http.calls.size).to eq(1)
      call = http.calls.first
      expect(call.verb).to eq(:post_json)
      expect(URI(call.url).path).to eq(issue_token_path)
      expect(call.headers).to include("Content-Type" => "application/json", "Connect-Protocol-Version" => "1")
      expect(call.params).to eq(
        "resource" => "https://api.acme.test", "scopes" => %w[read write], "workload" => "digest"
      )
    end

    it "2: Keycard-Org and Keycard-Zone are sent when set, and neither when unset" do
      with_tenant = agent_http
      mint(source(with_tenant, org: "org_1", zone: "zone_1"))
      without_tenant = agent_http
      mint(source(without_tenant))

      expect(with_tenant.calls.first.headers).to include("Keycard-Org" => "org_1", "Keycard-Zone" => "zone_1")
      expect(without_tenant.calls.first.headers.keys).not_to include("Keycard-Org", "Keycard-Zone")
    end

    it "3: appId is in the body when app_id is set, and absent as a key when unset" do
      declared = agent_http
      mint(source(declared, app_id: "urn:app:zazu"))
      undeclared = agent_http
      mint(source(undeclared))

      expect(declared.calls.first.params).to include("appId" => "urn:app:zazu")
      expect(undeclared.calls.first.params).not_to have_key("appId")
    end

    it "4: a resource a normalizer would rewrite is sent byte-identical" do
      resource = "HTTPS://API.Acme.TEST:443/a/./b/../c"
      http = agent_http
      mint(source(http), resource: resource)

      expect(http.calls.first.params["resource"]).to eq(resource)
    end

    it "5: an empty resource is a configuration error and nothing is sent" do
      http = agent_http
      # env: {} would itself fail resolution, so the error proves the resource
      # check runs first.
      subject = described_class.new(env: {}, http_client: http)

      expect { mint(subject, resource: "") }.to raise_error(Keycardai::OAuth::ConfigurationError, /resource/)
      expect(http.calls).to be_empty
    end

    it "6: an explicit socket is dialled over KEYCARD_SOCKET" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "explicit.sock")) do |explicit|
          FakeAgent.serve(File.join(dir, "env.sock")) do |from_env|
            mint(described_class.new(socket: explicit.path, env: { "KEYCARD_SOCKET" => from_env.path }))

            expect(explicit.requests.size).to eq(1)
            expect(from_env.requests).to be_empty
          end
        end
      end
    end

    it "7: KEYCARD_SOCKET in env is dialled, and the process environment is not read" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "env.sock")) do |agent|
          expect(ENV).not_to receive(:[])
          expect(ENV).not_to receive(:fetch)
          mint(described_class.new(env: { "KEYCARD_SOCKET" => agent.path }))

          expect(agent.requests.size).to eq(1)
        end
      end
    end

    it "8: an empty KEYCARD_SOCKET is treated as unset" do
      expect_network_error({ "KEYCARD_SOCKET" => "", "HOME" => "/h" },
                           "at /h/.local/state/keycard/run/agent.sock ")
    end

    it "9: HOME alone resolves the default socket under the state directory" do
      expect_network_error({ "HOME" => "/h" }, "at /h/.local/state/keycard/run/agent.sock ")
    end

    it "10: KEYCARD_HOME takes precedence over HOME" do
      expect_network_error({ "HOME" => "/h", "KEYCARD_HOME" => "/k" }, "at /k/.local/state/keycard/run/agent.sock ")
    end

    it "11: XDG_STATE_HOME replaces the home-relative state directory" do
      expect_network_error({ "HOME" => "/h", "XDG_STATE_HOME" => "/s" }, "at /s/keycard/run/agent.sock ")
    end

    it "12: XDG_RUNTIME_DIR replaces the run directory" do
      env = { "HOME" => "/h", "XDG_STATE_HOME" => "/s", "XDG_RUNTIME_DIR" => "/r" }

      expect_network_error(env, "at /r/keycard/agent.sock ")
    end

    it "13: KEYCARD_AGENT_DIR replaces the agent directory" do
      env = { "HOME" => "/h", "XDG_STATE_HOME" => "/s", "XDG_RUNTIME_DIR" => "/r", "KEYCARD_AGENT_DIR" => "/a" }

      expect_network_error(env, "at /a/agent.sock ")
    end

    it "14: keycard.toml in the working directory is not read" do
      Dir.mktmpdir do |dir|
        File.write(File.join(dir, "keycard.toml"), "[home]\ndir = \"/toml-home\"\n\n[agent]\nDir = \"/toml-agent\"\n")
        Dir.chdir(dir) do
          expect_network_error({ "HOME" => "/h" }, "at /h/.local/state/keycard/run/agent.sock ")
        end
      end
    end

    it "15: an empty env is a configuration error naming KEYCARD_SOCKET and HOME, with no connection" do
      expect(UNIXSocket).not_to receive(:new)

      expect { mint(described_class.new(env: {})) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /KEYCARD_SOCKET.*HOME/)
    end

    it "16: a failed connect names the resolved path, suggests keycard agent start, and creates nothing" do
      Dir.mktmpdir do |home|
        expect_network_error({ "HOME" => home },
                             a_string_including("#{home}/.local/state/keycard/run/agent.sock", "keycard agent start"))

        expect(Dir.children(home)).to be_empty
      end
    end

    it "17: a token is returned from the stub agent behind a real Unix socket" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock")) do |agent|
          token = mint(described_class.new(socket: agent.path, workload: "digest"), scopes: %w[read])

          expect(token.access_token).to eq("agent-token")
          request = agent.requests.first
          expect([request.verb, request.path]).to eq(["POST", issue_token_path])
          expect(request.headers).to include("content-type" => "application/json",
                                             "connect-protocol-version" => "1")
          expect(request.json).to eq("resource" => "https://api.acme.test", "scopes" => %w[read],
                                     "workload" => "digest")
        end
      end
    end

    it "18: the same resource and scopes requested twice reach the agent twice" do
      http = agent_http
      subject = source(http)
      2.times { mint(subject, scopes: %w[read]) }

      expect(http.calls.size).to eq(2)
    end

    it "24: a response with no expiresAt has a nil expires_in" do
      expect(mint(source(agent_http)).expires_in).to be_nil
    end

    it "25: an expiresAt already in the past has expires_in 0" do
      http = agent_http(payload: { "token" => "t", "expiresAt" => "2020-01-01T00:00:00Z" })

      expect(mint(source(http)).expires_in).to eq(0)
    end

    it "26: an expiresAt with nine fractional digits is computed against the injected clock" do
      http = agent_http(payload: { "token" => "t", "expiresAt" => "2026-11-17T12:00:00.987654321Z" })
      clock = -> { Time.utc(2026, 11, 17, 11, 59, 0) }

      expect(mint(source(http, clock: clock)).expires_in).to eq(60)
    end

    it "27: scopes the agent reports become the token's scope" do
      http = agent_http(payload: { "token" => "t", "scopes" => %w[a b] })

      expect(mint(source(http), scopes: %w[a]).scope).to eq(%w[a b])
    end

    it "28: no reported scopes leaves scope absent, not the requested scopes" do
      expect(mint(source(agent_http), scopes: %w[a]).scope).to be_nil
    end

    it "29: each agent code is an AgentError with that code and message, and only its predicate matches" do
      predicates = {
        "permission_denied" => :declined?, "resource_exhausted" => :rate_limited?,
        "failed_precondition" => :prompter_unavailable?, "unauthenticated" => :authorization_required?,
        "not_found" => :application_not_found?, "unavailable" => :unavailable?, "invalid_argument" => nil
      }
      predicates.each do |code, predicate|
        http = agent_http(status: 403, payload: { "code" => code, "message" => "because #{code}" })
        error = error_from { mint(source(http)) }

        expect(error).to be_a(Keycardai::OAuth::AgentError)
        expect([error.code, error.message]).to eq([code, "because #{code}"])
        expect(predicates.values.compact.select { |name| oauth.public_send(name, error) })
          .to eq([predicate].compact)
      end
    end

    it "30: the predicates still match an agent error the caller wrapped" do
      http = agent_http(status: 403, payload: { "code" => "permission_denied", "message" => "declined" })
      wrapped = error_from do
        mint(source(http))
      rescue Keycardai::OAuth::AgentError
        raise "token for the digest failed"
      end

      expect(wrapped).not_to be_a(Keycardai::OAuth::AgentError)
      expect(oauth.declined?(wrapped)).to be(true)
    end

    it "31: a non-200 response with a non-JSON body is an HTTPError carrying the status" do
      http = agent_http(status: 502, payload: "<html>bad gateway</html>")

      expect { mint(source(http)) }.to raise_error(Keycardai::OAuth::HTTPError) { |e|
        expect(e.status).to eq(502)
        expect(e).not_to be_a(Keycardai::OAuth::AgentError)
      }
    end

    it "32: a 200 with an empty token, a missing token, or a non-JSON body is an AgentResponseError" do
      [{ "token" => "" }, { "expiresAt" => "2030-01-01T00:00:00Z" }, "not json"].each do |payload|
        expect { mint(source(agent_http(payload: payload))) }
          .to raise_error(Keycardai::OAuth::AgentResponseError) { |e| expect(e.retryable?).to be(false) }
      end
    end

    it "33: a token containing a C0 control or DEL is an AgentResponseError that does not echo the token" do
      ["\r\nInjected: header", "\0", "\t", "\x1f", "\x7f"].each do |control|
        http = agent_http(payload: { "token" => "secret#{control}tail" })

        expect { mint(source(http)) }.to raise_error(Keycardai::OAuth::AgentResponseError) { |e|
          expect(e.message).not_to include("secret")
        }
      end
      expect(mint(source(agent_http(payload: { "token" => "printable-é~!" }))).access_token).to eq("printable-é~!")
    end

    it "34: retryable? is true for resource_exhausted and unavailable only" do
      codes = %w[permission_denied resource_exhausted failed_precondition unauthenticated not_found
                 unavailable invalid_argument]
      retryable = codes.select { |code| Keycardai::OAuth::AgentError.new("", code: code).retryable? }

      expect(retryable).to eq(%w[resource_exhausted unavailable])
    end

    describe Keycardai::OAuth::ResourceTransport do
      let(:stub_source) do
        Class.new do
          attr_reader :calls

          def initialize(error: nil)
            @error = error
            @calls = []
          end

          def resource_token(resource:, scopes: [])
            @calls << [resource, scopes]
            raise @error if @error

            Keycardai::OAuth::TokenResponse.new(access_token: "resource-token", token_type: "Bearer",
                                                expires_in: nil, scope: nil, issued_token_type: nil,
                                                refresh_token: nil, id_token: nil, raw: {})
          end
        end
      end
      let(:resource_http) { FakeHTTPClient.new { |_url, _params| json_response({ "ok" => true }) } }

      it "35: the outgoing request carries Authorization: Bearer <token>" do
        source = stub_source.new
        transport = described_class.new(source: source, resource: "https://api.acme.test", scopes: %w[read],
                                        http_client: resource_http)
        transport.get("https://api.acme.test/items")

        expect(resource_http.calls.first.headers).to include("Authorization" => "Bearer resource-token")
        expect(source.calls).to eq([["https://api.acme.test", %w[read]]])
      end

      it "36: a declined source error reaches the caller unwrapped and no request is sent" do
        declined = Keycardai::OAuth::AgentError.new("declined", code: "permission_denied")
        transport = described_class.new(source: stub_source.new(error: declined), resource: "https://api.acme.test",
                                        http_client: resource_http)

        expect { transport.get("https://api.acme.test/items") }.to raise_error(declined) { |e|
          expect(Keycardai::OAuth.declined?(e)).to be(true)
        }
        expect(resource_http.calls).to be_empty
      end

      it "37: a transport without a source, then without a resource, is a configuration error" do
        expect { described_class.new(resource: "https://api.acme.test") }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /source/)
        expect { described_class.new(source: stub_source.new) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /resource/)
      end

      it "38: the caller's headers are unchanged and the existing Authorization is replaced on the copy" do
        headers = { "authorization" => "Basic old", "Accept" => "application/json" }.freeze
        transport = described_class.new(source: stub_source.new, resource: "https://api.acme.test",
                                        http_client: resource_http)
        transport.post_json("https://api.acme.test/items", { "name" => "x" }, headers: headers)

        expect(headers).to eq("authorization" => "Basic old", "Accept" => "application/json")
        expect(resource_http.calls.first.headers)
          .to eq("Accept" => "application/json", "Authorization" => "Bearer resource-token")
      end
    end
  end

  describe "beyond the spec rows" do
    it "construction is inert: an unresolvable environment raises only at the first mint" do
      subject = nil
      expect { subject = described_class.new(env: {}) }.not_to raise_error
      expect { mint(subject) }.to raise_error(Keycardai::OAuth::ConfigurationError)
    end

    it "the default socket is a configuration error on Windows" do
      allow(Gem).to receive(:win_platform?).and_return(true)

      expect { mint(described_class.new(env: { "HOME" => "/h" })) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /KEYCARD_SOCKET.*Windows/)
    end

    it "a network error names the rule that chose an explicit socket, without the default-socket hint" do
      expect { mint(described_class.new(socket: "/nonexistent/agent.sock")) }
        .to raise_error(Keycardai::OAuth::NetworkError) { |e|
          expect(e.message).to include("/nonexistent/agent.sock", "the socket option")
          expect(e.message).not_to include("keycard agent start")
          expect(e.cause).to be_a(Keycardai::OAuth::NetworkError)
        }
    end

    ["2026-11-17 12:00:00", "2026-11-17T12:00:00", "2026-13-45T00:00:00Z", "2026-11-17T12:00:00.1234567890Z",
     1_795_000_000].each do |expires_at|
      it "an expiresAt of #{expires_at.inspect} is an AgentResponseError" do
        http = agent_http(payload: { "token" => "t", "expiresAt" => expires_at })

        expect { mint(source(http)) }.to raise_error(Keycardai::OAuth::AgentResponseError, /expiresAt/)
      end
    end

    it "an expiresAt with an offset and a lowercase t and z is accepted" do
      clock = -> { Time.utc(2026, 11, 17, 9, 59, 0) }
      offset = agent_http(payload: { "token" => "t", "expiresAt" => "2026-11-17T12:00:00+02:00" })
      lowercase = agent_http(payload: { "token" => "t", "expiresAt" => "2026-11-17t10:00:00z" })

      expect(mint(source(offset, clock: clock)).expires_in).to eq(60)
      expect(mint(source(lowercase, clock: clock)).expires_in).to eq(60)
    end

    ["a b", %w[a] + [1]].each do |scopes|
      it "a scopes value of #{scopes.inspect}, not a list of strings, is an AgentResponseError" do
        http = agent_http(payload: { "token" => "t", "scopes" => scopes })

        expect { mint(source(http)) }.to raise_error(Keycardai::OAuth::AgentResponseError, /scopes/)
      end
    end

    it "an empty reported scopes list leaves scope absent" do
      expect(mint(source(agent_http(payload: { "token" => "t", "scopes" => [] }))).scope).to be_nil
    end

    it "the token type is Bearer" do
      expect(mint(source(agent_http)).token_type).to eq("Bearer")
    end

    it "the socket is resolved again on every call, so a changed environment takes effect on the next" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "first.sock")) do |first|
          FakeAgent.serve(File.join(dir, "second.sock")) do |second|
            env = { "KEYCARD_SOCKET" => first.path }
            subject = described_class.new(env: env)
            mint(subject)
            env["KEYCARD_SOCKET"] = second.path
            mint(subject)

            expect([first.requests.size, second.requests.size]).to eq([1, 1])
          end
        end
      end
    end

    {
      "org" => { org: "org\r\nX-Injected: 1" },
      "zone" => { zone: "zone\0" }
    }.each do |name, options|
      it "a control character in #{name} is a configuration error and nothing is sent" do
        http = agent_http

        expect { mint(source(http, **options)) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /#{name} contains a control character/)
        expect(http.calls).to be_empty
      end
    end

    it "a string that is not valid UTF-8 is a configuration error and nothing is sent" do
      http = agent_http

      expect { mint(source(http), resource: "https://api.acme.test/\xff") }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /resource is not valid UTF-8/)
      expect { mint(source(http, workload: "caf\xC3\xA9".b)) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /workload is not valid UTF-8/)
      expect { mint(source(http), scopes: ["read", "\xff"]) }
        .to raise_error(Keycardai::OAuth::ConfigurationError, /scopes is not valid UTF-8/)
      expect(http.calls).to be_empty
    end

    it "an over-long socket path is a NetworkError naming it" do
      path = "/#{"a" * 200}/agent.sock"

      expect { mint(described_class.new(socket: path)) }
        .to raise_error(Keycardai::OAuth::NetworkError, a_string_including(path, "the socket option"))
    end

    it "a chunked response over the socket is decoded" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock"), chunked: true) do |agent|
          token = mint(described_class.new(socket: agent.path))

          expect(token.access_token).to eq("agent-token")
        end
      end
    end

    it "a timeout bounds a request the agent never answers" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock"), ->(_request) { sleep }) do |agent|
          expect { mint(described_class.new(socket: agent.path, timeout: 0.1)) }
            .to raise_error(Keycardai::OAuth::NetworkError, /timed out/)
        end
      end
    end
  end

  describe "Integration Tests, against a fake agent" do
    def zone_agent(declined_scopes: [], applications: [])
      lambda do |request|
        body = request.json
        if body.key?("appId") && !applications.include?(body["appId"])
          [404, { "code" => "not_found", "message" => "no application #{body["appId"]}" }]
        elsif body["scopes"].intersect?(declined_scopes)
          [403, { "code" => "permission_denied", "message" => "the request was declined" }]
        else
          [200, { "token" => "zone-token-for-#{body["resource"]}", "expiresAt" => "2099-01-01T00:00:00Z" }]
        end
      end
    end

    it "1: a mint with no application credential returns the agent's token" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock"), zone_agent) do |agent|
          token = mint(described_class.new(socket: agent.path))

          expect(token.access_token).to eq("zone-token-for-https://api.acme.test")
          expect(token.expires_in).to be_positive
        end
      end
    end

    it "2 and 3: requests through a resource transport each reach the agent and carry its token" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock"), zone_agent) do |agent|
          resource_server = FakeHTTPClient.new { |_url, _params| json_response({ "ok" => true }) }
          transport = Keycardai::OAuth::ResourceTransport.new(
            source: described_class.new(socket: agent.path), resource: "https://api.acme.test",
            http_client: resource_server
          )
          statuses = Array.new(2) { transport.get("https://api.acme.test/items").status }

          expect(statuses).to eq([200, 200])
          expect(agent.requests.size).to eq(2)
          expect(resource_server.calls.map { |call| call.headers["Authorization"] })
            .to all(eq("Bearer zone-token-for-https://api.acme.test"))
        end
      end
    end

    it "4: a declined prompt is declined?" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock"), zone_agent(declined_scopes: %w[admin])) do |agent|
          expect { mint(described_class.new(socket: agent.path), scopes: %w[admin]) }
            .to raise_error(Keycardai::OAuth::AgentError) { |e| expect(oauth.declined?(e)).to be(true) }
        end
      end
    end

    it "5: an app_id naming no application is application_not_found?" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock"), zone_agent) do |agent|
          expect { mint(described_class.new(socket: agent.path, app_id: "urn:app:missing")) }
            .to raise_error(Keycardai::OAuth::AgentError) { |e| expect(oauth.application_not_found?(e)).to be(true) }
        end
      end
    end

    it "6: a declared app_id reaches the agent" do
      FakeAgent.short_tmpdir do |dir|
        FakeAgent.serve(File.join(dir, "agent.sock"), zone_agent(applications: %w[urn:app:zazu])) do |agent|
          mint(described_class.new(socket: agent.path, app_id: "urn:app:zazu"))

          expect(agent.requests.first.json).to include("appId" => "urn:app:zazu")
        end
      end
    end

    it "7: with no socket and no KEYCARD_SOCKET, the default socket reaches the daemon with org and zone" do
      FakeAgent.short_tmpdir do |home|
        run_dir = File.join(home, ".local", "state", "keycard", "run")
        FileUtils.mkdir_p(run_dir)
        FakeAgent.serve(File.join(run_dir, "agent.sock"), zone_agent) do |agent|
          token = mint(described_class.new(env: { "HOME" => home }, org: "org_1", zone: "zone_1"))

          expect(token.access_token).to eq("zone-token-for-https://api.acme.test")
          expect(agent.requests.first.headers).to include("keycard-org" => "org_1", "keycard-zone" => "zone_1")
        end
      end
    end

    it "8: with the daemon stopped, the network error names the default socket and suggests keycard agent start" do
      FakeAgent.short_tmpdir do |runtime|
        path = File.join(runtime, "keycard", "agent.sock")

        expect_network_error({ "XDG_RUNTIME_DIR" => runtime, "HOME" => "/h" },
                             a_string_including(path, "the default agent socket", "keycard agent start"))
      end
    end
  end
end
