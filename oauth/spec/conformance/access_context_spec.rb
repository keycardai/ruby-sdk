# frozen_string_literal: true

# Conformance suite for keycard-sdk-spec specs/delegated-access/access-context.md.
# Each example maps to a row of the spec's Unit Tests table.
RSpec.describe Keycardai::OAuth::AccessContext do
  let(:token) { Keycardai::OAuth::TokenResponse.from_wire({ "access_token" => "at_a" }) }
  let(:upstream_error) { Keycardai::OAuth::OAuthError.new("rejected", error: "invalid_grant", status: 400) }

  def context_with_token
    described_class.new("https://a.test" => token)
  end

  def context_with_error
    described_class.new.tap { |ctx| ctx.set_resource_error("https://a.test", upstream_error) }
  end

  it "1: access returns the token for a successful resource" do
    expect(context_with_token.access("https://a.test")).to eq(token)
  end

  it "2: access throws ResourceAccessError (resource_error) for a failed resource" do
    expect { context_with_error.access("https://a.test") }
      .to raise_error(Keycardai::OAuth::ResourceAccessError) { |e|
        expect(e.error_type).to eq("resource_error")
        expect(e.error_details).to eq(upstream_error)
      }
  end

  it "3: access throws ResourceAccessError (missing_token) for an ungranted resource" do
    expect { context_with_token.access("https://other.test") }
      .to raise_error(Keycardai::OAuth::ResourceAccessError) { |e|
        expect(e.error_type).to eq("missing_token")
        expect(e.available_resources).to eq(["https://a.test"])
      }
  end

  it "4: access throws ResourceAccessError (global_error) when a global error is set" do
    ctx = context_with_token
    ctx.set_error(upstream_error)

    expect { ctx.access("https://a.test") }
      .to raise_error(Keycardai::OAuth::ResourceAccessError) { |e| expect(e.error_type).to eq("global_error") }
  end

  it "5: resource_error returns the recorded error for a failed resource" do
    expect(context_with_error.resource_error("https://a.test")).to eq(upstream_error)
  end

  it "6: resource_error returns nil for a successful resource" do
    expect(context_with_token.resource_error("https://a.test")).to be_nil
  end

  it "7: errors? is false when all exchanges succeeded" do
    expect(context_with_token.errors?).to be(false)
  end

  it "8: errors? is true when a per-resource exchange failed" do
    expect(context_with_error.errors?).to be(true)
  end

  it "9: errors? is true when a global error is set" do
    ctx = described_class.new
    ctx.set_error(upstream_error)

    expect(ctx.errors?).to be(true)
  end

  it "10: error? is false when only per-resource errors exist" do
    expect(context_with_error.error?).to be(false)
  end

  it "11: status is success when all exchanges succeeded" do
    expect(context_with_token.status).to eq("success")
  end

  it "12: status is partial_error when a per-resource exchange failed" do
    expect(context_with_error.status).to eq("partial_error")
  end

  it "13: status is error when a global error is set" do
    ctx = context_with_error
    ctx.set_error(upstream_error)

    expect(ctx.status).to eq("error")
  end

  it "14: successful_resources lists only resources with tokens" do
    ctx = context_with_token
    ctx.set_resource_error("https://b.test", upstream_error)

    expect(ctx.successful_resources).to eq(["https://a.test"])
  end

  it "15: failed_resources lists only resources with recorded errors" do
    ctx = context_with_token
    ctx.set_resource_error("https://b.test", upstream_error)

    expect(ctx.failed_resources).to eq(["https://b.test"])
  end

  it "16: a later set_resource_error clears the token, and a later set_token clears the error" do
    ctx = context_with_token
    ctx.set_resource_error("https://a.test", upstream_error)
    expect(ctx.successful_resources).to be_empty
    expect(ctx.failed_resources).to eq(["https://a.test"])

    ctx.set_token("https://a.test", token)
    expect(ctx.successful_resources).to eq(["https://a.test"])
    expect(ctx.failed_resources).to be_empty
  end

  describe "exchange_tokens_for_resources" do
    let(:zone) { ZoneFixture.new }

    def client(http)
      Keycardai::OAuth::TokenExchangeClient.new(
        issuer: zone.issuer, client_id: "cid", client_secret: "csecret", http_client: http
      )
    end

    it "populates tokens for every successful exchange" do
      http = FakeHTTPClient.new do |url, params|
        next json_response(zone.metadata) if url == zone.metadata_url

        json_response({ "access_token" => "at_#{params["resource"][%r{https://(\w+)}, 1]}" })
      end

      ctx = Keycardai::OAuth.exchange_tokens_for_resources(
        client: client(http), resources: %w[https://a.test https://b.test], subject_token: "at_subject",
        request_scopes: { "https://a.test" => "read" }
      )

      expect(ctx.status).to eq("success")
      expect(ctx.access("https://a.test").access_token).to eq("at_a")
      expect(ctx.access("https://b.test").access_token).to eq("at_b")
      scoped = http.calls.find { |call| call.params&.fetch("resource", nil) == "https://a.test" }
      expect(scoped.params).to include("scope" => "read")
    end

    it "records a per-resource error without aborting the remaining exchanges" do
      http = FakeHTTPClient.new do |url, params|
        next json_response(zone.metadata) if url == zone.metadata_url

        if params["resource"] == "https://bad.test"
          json_response({ "error" => "invalid_target" }, status: 400)
        else
          json_response({ "access_token" => "at_good" })
        end
      end

      ctx = Keycardai::OAuth.exchange_tokens_for_resources(
        client: client(http), resources: %w[https://bad.test https://good.test], subject_token: "at_subject"
      )

      expect(ctx.status).to eq("partial_error")
      expect(ctx.access("https://good.test").access_token).to eq("at_good")
      expect(ctx.resource_error("https://bad.test")).to be_a(Keycardai::OAuth::OAuthError)
    end

    it "impersonates instead of exchanging when user_identifier is given" do
      http = FakeHTTPClient.new do |url, _params|
        url == zone.metadata_url ? json_response(zone.metadata) : json_response({ "access_token" => "at_imp" })
      end

      ctx = Keycardai::OAuth.exchange_tokens_for_resources(
        client: client(http), resources: ["https://a.test"], user_identifier: "usr_123"
      )

      call = http.calls.find { |c| c.url == zone.token_url }
      expect(call.params["subject_token_type"]).to eq("urn:keycard:params:oauth:token-type:substitute-user")
      expect(ctx.access("https://a.test").access_token).to eq("at_imp")
    end
  end
end
