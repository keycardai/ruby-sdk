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
end
