# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/delegated-access/grant-decorator.md.
# Each example maps to a row of the spec's Unit Tests table (row 3 follows the
# fail-fast 401 contract Python and TS converged on via ECO-79).
RSpec.describe "Grant decorator" do
  let(:zone) { MiniZone.new }
  let(:probe) { ProbeApp.new }

  def zone_http(&token_handler)
    FakeHTTPClient.new do |url, params|
      next http_json(zone.metadata) if url == zone.metadata_url

      token_handler ? token_handler.call(params) : http_json({ "access_token" => "at_#{params["resource"]}" })
    end
  end

  def provider(http)
    Keycardai::MCP::AuthProvider.new(zone_url: zone.issuer, client_id: "cid", client_secret: "csecret",
                                     http_client: http)
  end

  def authenticated_env
    rack_env.merge(Keycardai::MCP::ENV_AUTH_INFO => access_token(token: "at_caller"))
  end

  it "1: two successful exchanges expose a token per resource with no errors" do
    middleware = provider(zone_http).grant(%w[https://a.test https://b.test]).new(probe)

    status, = middleware.call(authenticated_env)

    expect(status).to eq(200)
    context = Keycardai::MCP.access_context(probe.seen_env)
    expect(context.errors?).to be(false)
    expect(context.access("https://a.test").access_token).to eq("at_https://a.test")
    expect(context.access("https://b.test").access_token).to eq("at_https://b.test")
  end

  it "2: a failing resource records an error while the handler still runs" do
    http = zone_http do |params|
      if params["resource"] == "https://bad.test"
        http_json({ "error" => "invalid_target" }, status: 400)
      else
        http_json({ "access_token" => "at_good" })
      end
    end
    middleware = provider(http).grant(%w[https://bad.test https://good.test]).new(probe)

    status, = middleware.call(authenticated_env)

    expect(status).to eq(200)
    context = Keycardai::MCP.access_context(probe.seen_env)
    expect(context.status).to eq("partial_error")
    expect(context.access("https://good.test").access_token).to eq("at_good")
    expect(context.resource_error("https://bad.test")).to be_a(Keycardai::OAuth::OAuthError)
  end

  it "3: an unauthenticated request is rejected 401 fail-fast and the handler does not run" do
    middleware = provider(zone_http).grant("https://a.test").new(probe)

    status, headers, = middleware.call(rack_env)

    expect(status).to eq(401)
    expect(headers["www-authenticate"]).to include("resource_metadata=")
    expect(probe.ran?).to be(false)
  end

  it "4: a user_identifier turns the exchange into a substitute-user impersonation" do
    http = zone_http
    resolver = ->(env) { env["HTTP_X_USER"] }
    middleware = provider(http).grant("https://a.test", user_identifier: resolver).new(probe)

    middleware.call(authenticated_env.merge("HTTP_X_USER" => "usr_777"))

    token_call = http.calls.find { |call| call.url == zone.token_url }
    expect(token_call.params["subject_token_type"]).to eq("urn:keycard:params:oauth:token-type:substitute-user")
    header, payload = token_call.params["subject_token"].split(".").first(2).map do |part|
      padded = part.tr("-_", "+/")
      JSON.parse((padded + ("=" * ((4 - (padded.length % 4)) % 4))).unpack1("m0"))
    end
    expect(header["typ"]).to eq("vnd.kc.su+jwt")
    expect(payload).to eq("sub" => "usr_777")
  end

  it "5: stacked grants union their resources into one merged AccessContext" do
    shared = provider(zone_http)
    inner = shared.grant("https://b.test").new(probe)
    outer = shared.grant("https://a.test", request_scopes: "read").new(inner)

    status, = outer.call(authenticated_env)

    expect(status).to eq(200)
    context = Keycardai::MCP.access_context(probe.seen_env)
    expect(context.successful_resources).to contain_exactly("https://a.test", "https://b.test")
  end
end
