# frozen_string_literal: true

require "net/http"

# Behavioral suite for the high-level authenticate loopback flow of
# keycard-sdk-spec specs/oauth-client/authorization-code-pkce.md, exercised
# against a real loopback server with a fake browser standing in for the
# user. The spec's unit table covers the primitives (see
# authorization_code_pkce_spec.rb); the live-zone round trip stays in the
# integration table for the E2E phase.
RSpec.describe "Authenticate loopback flow" do
  let(:zone) { ZoneFixture.new }

  def token_http
    FakeHTTPClient.new do |url, _params|
      url == zone.metadata_url ? json_response(zone.metadata) : json_response({ "access_token" => "at_user" })
    end
  end

  # A browser stand-in: parses the authorize URL and immediately drives the
  # redirect back to the loopback server, transforming the query as told.
  def fake_browser(&transform)
    lambda do |authorize_url|
      Thread.new do
        uri = URI(authorize_url)
        params = URI.decode_www_form(uri.query).to_h
        redirect = URI(params.fetch("redirect_uri"))
        query = transform.call(params)
        Net::HTTP.get(URI("#{redirect}?#{URI.encode_www_form(query)}"))
      end
    end
  end

  def authenticate(browser, **options)
    Keycardai::OAuth.authenticate(
      issuer: zone.issuer, client_id: "cid", port: 0, callback_timeout: 5,
      http_client: token_http, browser_opener: browser, **options
    )
  end

  it "completes the round trip: PKCE + state on the URL, code received, token exchanged" do
    seen = nil
    browser = fake_browser do |params|
      seen = params
      { "code" => "auth-code", "state" => params.fetch("state") }
    end

    response = authenticate(browser, scope: "openid")

    expect(response.access_token).to eq("at_user")
    expect(seen).to include("response_type" => "code", "client_id" => "cid", "scope" => "openid")
    expect(seen["code_challenge"]).not_to be_nil
    expect(seen["state"]).not_to be_nil
    expect(seen["redirect_uri"]).to match(%r{\Ahttp://127\.0\.0\.1:\d+/callback\z})
  end

  it "with a credential, puts client_id on the authorize URL only and authenticates the exchange with it" do
    seen = nil
    http = token_http
    browser = fake_browser do |params|
      seen = params
      { "code" => "auth-code", "state" => params.fetch("state") }
    end
    credential = Keycardai::OAuth::WorkloadIdentity.new(source: -> { "platform-token" }, client_id: "cid")

    Keycardai::OAuth.authenticate(issuer: zone.issuer, client_id: "cid", credential: credential, port: 0,
                                  callback_timeout: 5, http_client: http, browser_opener: browser)

    token_call = http.calls.find { |call| call.url == zone.token_url }
    expect(seen).to include("client_id" => "cid")
    expect(seen).not_to have_key("client_assertion")
    expect(token_call.params).to include("client_id" => "cid", "client_assertion" => "platform-token")
    expect(token_call.headers).not_to have_key("Authorization")
  end

  it "rejects a credential combined with a client_secret before opening the browser" do
    credential = Keycardai::OAuth::ClientSecret.new("cid", "csecret")
    opened = false

    expect { authenticate(->(_url) { opened = true }, credential: credential, client_secret: "csecret") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
    expect(opened).to be(false)
  end

  it "rejects a redirect whose state does not match" do
    browser = fake_browser { |_params| { "code" => "auth-code", "state" => "forged" } }

    expect { authenticate(browser) }
      .to raise_error(Keycardai::OAuth::ProtocolError) { |e| expect(e.code).to eq("state_mismatch") }
  end

  it "surfaces an error carried on the redirect as a typed OAuth error" do
    browser = fake_browser { |_params| { "error" => "access_denied", "state" => "unused" } }

    expect { authenticate(browser) }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e| expect(e.error).to eq("access_denied") }
  end

  it "times out when the user never completes the redirect" do
    idle_browser = ->(_url) {}

    expect { authenticate(idle_browser, callback_timeout: 0.2) }
      .to raise_error(Keycardai::OAuth::InteractionTimeoutError)
  end

  describe "34: a WorkloadIdentity credential without client_id" do
    let(:credential) { Keycardai::OAuth::WorkloadIdentity.new(source: -> { raise "source called" }) }
    let(:message) do
      "WorkloadIdentity: client_id is required for interactive grants (the public ID of a v2 token credential)"
    end

    it "authenticate raises a configuration error before discovery or opening the browser" do
      http = token_http
      opened = false

      expect do
        Keycardai::OAuth.authenticate(issuer: zone.issuer, client_id: "cid", credential: credential, port: 0,
                                      callback_timeout: 1, http_client: http,
                                      browser_opener: ->(_url) { opened = true })
      end.to raise_error(Keycardai::OAuth::ConfigurationError, message)
      expect(http.calls).to be_empty
      expect(opened).to be(false)
    end

    it "authenticate_from_challenge raises a configuration error before the resource metadata fetch" do
      http = token_http
      header = 'Bearer resource_metadata="https://tool.example.com/.well-known/oauth-protected-resource"'

      expect do
        Keycardai::OAuth.authenticate_from_challenge(header, client_id: "cid", credential: credential, port: 0,
                                                             callback_timeout: 1, http_client: http,
                                                             browser_opener: ->(_url) {})
      end.to raise_error(Keycardai::OAuth::ConfigurationError, message)
      expect(http.calls).to be_empty
    end
  end

  describe "resolve_issuer_from_challenge" do
    it "fetches the challenge's resource metadata and returns its first authorization server" do
      http = FakeHTTPClient.new do |url, _params|
        expect(url).to eq("https://tool.example.com/.well-known/oauth-protected-resource")
        json_response({ "authorization_servers" => [zone.issuer] })
      end
      header = 'Bearer resource_metadata="https://tool.example.com/.well-known/oauth-protected-resource"'

      expect(Keycardai::OAuth.resolve_issuer_from_challenge(header, http_client: http)).to eq(zone.issuer)
    end

    it "rejects a challenge without resource_metadata and metadata without authorization servers" do
      expect { Keycardai::OAuth.resolve_issuer_from_challenge("Bearer realm=\"x\"", http_client: token_http) }
        .to raise_error(Keycardai::OAuth::ProtocolError)

      empty = FakeHTTPClient.new { |_url, _params| json_response({}) }
      expect do
        Keycardai::OAuth.resolve_issuer_from_challenge('Bearer resource_metadata="https://t.test/x"',
                                                       http_client: empty)
      end.to raise_error(Keycardai::OAuth::ProtocolError)
    end
  end

  # Unit rows 23 to 32 (spec-version 7): client authentication goes to an
  # issuer resolved from a challenge only when the allow-list includes it.
  # Row 33 does not apply because Ruby has no challenge-entered refresh.
  describe "authenticate_from_challenge issuer pinning" do
    let(:prm_url) { "https://tool.example.com/.well-known/oauth-protected-resource" }
    let(:header) { %(Bearer resource_metadata="#{prm_url}") }

    def challenge_http(issuer)
      FakeHTTPClient.new do |url, _params|
        case url
        when prm_url then json_response({ "authorization_servers" => [issuer] })
        when zone.metadata_url then json_response(zone.metadata)
        else json_response({ "access_token" => "at_user" })
        end
      end
    end

    def redirecting_browser
      fake_browser { |params| { "code" => "auth-code", "state" => params.fetch("state") } }
    end

    def from_challenge(http, browser, **options)
      Keycardai::OAuth.authenticate_from_challenge(
        header, http_client: http, client_id: "cid", port: 0, callback_timeout: 5,
                browser_opener: browser, **options
      )
    end

    [nil, []].each do |allowed|
      it "rejects client_secret with allowed_issuers #{allowed.inspect} before any request" do
        http = challenge_http(zone.issuer)
        browser = ->(_url) { raise "browser should not open" }

        expect { from_challenge(http, browser, client_secret: "shh", allowed_issuers: allowed) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /allowed_issuers/)
        expect(http.requests).to be_empty
      end
    end

    describe "with a WorkloadIdentity credential" do
      let(:credential) { Keycardai::OAuth::WorkloadIdentity.new(source: -> { "platform-token" }, client_id: "cid") }

      it "24: rejects a credential without allowed_issuers before any request" do
        http = challenge_http(zone.issuer)
        browser = ->(_url) { raise "browser should not open" }

        expect { from_challenge(http, browser, credential: credential) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /allowed_issuers/)
        expect(http.requests).to be_empty
      end

      it "26: sends the client assertion to an allowed issuer" do
        http = challenge_http(zone.issuer)

        response = from_challenge(http, redirecting_browser, credential: credential, allowed_issuers: [zone.issuer])

        expect(response.access_token).to eq("at_user")
        token_call = http.calls.find { |call| call.verb == :post && call.url == zone.token_url }
        expect(token_call.params).to include("client_assertion" => "platform-token")
      end
    end

    [nil, ""].each do |entry|
      it "rejects allowed_issuers containing #{entry.inspect} before any request" do
        http = challenge_http(zone.issuer)
        browser = ->(_url) { raise "browser should not open" }

        expect { from_challenge(http, browser, client_secret: "shh", allowed_issuers: [entry]) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /allowed_issuers entries must be non-empty strings/)
        expect(http.requests).to be_empty
      end
    end

    [{ client_secret: "shh" }, {}].each do |auth|
      it "rejects a resolved issuer outside allowed_issuers (#{auth.empty? ? "public" : "client_secret"})" do
        http = challenge_http(zone.issuer)
        browser = ->(_url) { raise "browser should not open" }

        expect { from_challenge(http, browser, allowed_issuers: ["https://trusted.example.com"], **auth) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /#{Regexp.escape(zone.issuer)}.*not in allowed_issuers/)
        expect(http.requests).to eq([prm_url])
      end
    end

    it "sends client_secret to an allowed issuer, compared without a trailing slash" do
      http = challenge_http("#{zone.issuer}/")

      response = from_challenge(http, redirecting_browser, client_secret: "shh", allowed_issuers: [zone.issuer])

      expect(response.access_token).to eq("at_user")
      token_call = http.calls.find { |call| call.verb == :post }
      expect(token_call.headers["Authorization"]).to start_with("Basic ")
    end

    it "lets a public client omit allowed_issuers" do
      response = from_challenge(challenge_http(zone.issuer), redirecting_browser)

      expect(response.access_token).to eq("at_user")
    end

    describe "with a multi-zone ClientSecret credential" do
      def multi_zone(*issuers)
        Keycardai::OAuth::ClientSecret.new(issuers.each_with_index.to_h { |iss, n| [iss, ["id-#{n}", "secret-#{n}"]] })
      end

      it "proceeds when the resolved issuer is one of its zones" do
        credential = multi_zone("https://other.example.com", "#{zone.issuer}/")
        http = challenge_http(zone.issuer)
        received = nil
        without_partial_double_verification do
          allow(Keycardai::OAuth).to receive(:authenticate) { |**kw| (received = kw) && :token }

          expect(from_challenge(http, redirecting_browser, credential: credential)).to eq(:token)
        end

        expect(received).to include(issuer: zone.issuer, credential: credential)
        expect(http.requests).to eq([prm_url])
      end

      it "raises before any request to an issuer outside its zones" do
        credential = multi_zone("https://other.example.com", "https://third.example.com")
        http = challenge_http(zone.issuer)
        browser = ->(_url) { raise "browser should not open" }

        expect { from_challenge(http, browser, credential: credential) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /#{Regexp.escape(zone.issuer)}.*zone issuers/)
        expect(http.requests).to eq([prm_url])
      end

      it "uses an explicit allowed_issuers over its zones" do
        http = challenge_http(zone.issuer)
        browser = ->(_url) { raise "browser should not open" }

        expect do
          from_challenge(http, browser, credential: multi_zone(zone.issuer),
                                        allowed_issuers: ["https://trusted.example.com"])
        end.to raise_error(Keycardai::OAuth::ConfigurationError, /not in allowed_issuers/)
        expect(http.requests).to eq([prm_url])
      end

      it "still requires allowed_issuers for a single-zone ClientSecret" do
        http = challenge_http(zone.issuer)
        browser = ->(_url) { raise "browser should not open" }

        expect { from_challenge(http, browser, credential: Keycardai::OAuth::ClientSecret.new("cid", "shh")) }
          .to raise_error(Keycardai::OAuth::ConfigurationError, /allowed_issuers/)
        expect(http.requests).to be_empty
      end
    end
  end
end
