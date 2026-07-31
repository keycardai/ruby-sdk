# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/oauth-client/authorization-code-pkce.md.
# Each example maps to a row of the spec's Unit Tests table. The high-level
# authenticate loopback flow is covered by the spec's integration table only.
RSpec.describe "Authorization code with PKCE" do
  let(:zone) { ZoneFixture.new }
  let(:token_payload) { { "access_token" => "at_user", "token_type" => "Bearer" } }

  def token_http(payload = token_payload, status: 200)
    FakeHTTPClient.new do |url, _params|
      url == zone.metadata_url ? json_response(zone.metadata) : json_response(payload, status: status)
    end
  end

  def token_call(http)
    http.calls.find { |call| call.url == zone.token_url }
  end

  def exchange(http, **options)
    defaults = { code: "auth-code", code_verifier: "verifier", redirect_uri: "http://127.0.0.1:8765/callback" }
    Keycardai::OAuth.exchange_authorization_code(zone.issuer, http_client: http, **defaults, **options)
  end

  it "1: generates a 43-128 character unreserved-character verifier" do
    default_verifier = Keycardai::OAuth::PKCE.generate_code_verifier
    shortest = Keycardai::OAuth::PKCE.generate_code_verifier(length: 43)

    expect(default_verifier.length).to eq(128)
    expect(shortest.length).to eq(43)
    expect(default_verifier).to match(/\A[A-Za-z0-9\-._~]+\z/)
    expect { Keycardai::OAuth::PKCE.generate_code_verifier(length: 42) }.to raise_error(ArgumentError)
    expect { Keycardai::OAuth::PKCE.generate_code_verifier(length: 129) }.to raise_error(ArgumentError)
  end

  it "2: derives the S256 challenge as BASE64URL(SHA-256(verifier))" do
    # Test vector from RFC 7636 appendix B.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    challenge = Keycardai::OAuth::PKCE.generate_code_challenge(verifier)

    expect(challenge).to eq("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    expect(Keycardai::OAuth::PKCE.generate_code_challenge(verifier, method: "plain")).to eq(verifier)
  end

  it "3: builds the authorize URL with the PKCE and scope parameters" do
    pair = Keycardai::OAuth::PKCE.generate_pair
    url = Keycardai::OAuth.build_authorize_url(
      "#{zone.issuer}/oauth/authorize",
      client_id: "cid", redirect_uri: "http://127.0.0.1:8765/callback",
      code_challenge: pair.code_challenge, code_challenge_method: pair.code_challenge_method,
      scope: "openid profile"
    )

    uri = URI(url)
    params = URI.decode_www_form(uri.query).to_h
    expect("#{uri.scheme}://#{uri.host}#{uri.path}").to eq("#{zone.issuer}/oauth/authorize")
    expect(params).to include(
      "response_type" => "code",
      "client_id" => "cid",
      "redirect_uri" => "http://127.0.0.1:8765/callback",
      "code_challenge" => pair.code_challenge,
      "code_challenge_method" => "S256",
      "scope" => "openid profile"
    )
  end

  it "4: exchanges a code with grant_type, code, code_verifier, and redirect_uri in the body" do
    http = token_http
    response = exchange(http)

    expect(token_call(http).params).to include(
      "grant_type" => "authorization_code",
      "code" => "auth-code",
      "code_verifier" => "verifier",
      "redirect_uri" => "http://127.0.0.1:8765/callback"
    )
    expect(response.access_token).to eq("at_user")
  end

  it "5: a public client sends client_id in the body with no Basic header" do
    http = token_http
    exchange(http, client_id: "cid")

    call = token_call(http)
    expect(call.params).to include("client_id" => "cid")
    expect(call.headers).not_to have_key("Authorization")
  end

  it "6: a confidential client authenticates with HTTP Basic and omits client_id from the body" do
    http = token_http
    exchange(http, client_id: "cid", client_secret: "csecret")

    call = token_call(http)
    expect(call.headers["Authorization"]).to eq("Basic #{["cid:csecret"].pack("m0")}")
    expect(call.params).not_to have_key("client_id")
  end

  it "7: surfaces an OAuth error response as a typed error with its fields" do
    http = token_http({ "error" => "invalid_grant", "error_description" => "code already used" }, status: 400)

    expect { exchange(http) }
      .to raise_error(Keycardai::OAuth::OAuthError) { |e|
        expect(e.error).to eq("invalid_grant")
        expect(e.error_description).to eq("code already used")
      }
  end

  it "rejects a client_secret without a client_id" do
    expect { exchange(token_http, client_secret: "csecret") }
      .to raise_error(Keycardai::OAuth::ConfigurationError)
  end
end
