# frozen_string_literal: true

# A token-endpoint response whose body does not decompress, through the real
# NetHTTPClient. A 2xx is a malformed token response. Any other status is the
# error for that status, without an OAuth error body. Not a network error.
RSpec.describe Keycardai::OAuth::TokenRequests do
  after { @server&.close }

  def client_credentials_client(token_response)
    @server = RawHTTPServer.new do |_method, path|
      if path == "/.well-known/oauth-authorization-server"
        RawHTTPServer.json(200, { "issuer" => @server.url(""), "token_endpoint" => @server.url("/oauth/token") })
      else
        token_response
      end
    end
    Keycardai::OAuth::ClientCredentialsClient.new(issuer: @server.url(""), client_id: "cid", client_secret: "csecret")
  end

  it "raises ProtocolError invalid_response for a 2xx, with the Zlib error as its cause" do
    client = client_credentials_client(RawHTTPServer.corrupt_gzip(200))

    expect { client.request_token }
      .to raise_error(Keycardai::OAuth::ProtocolError,
                      "token response body does not decompress: Zlib::DataError") { |e|
        expect(e.code).to eq("invalid_response")
        expect(e.cause).to be_an_instance_of(Zlib::DataError)
      }
  end

  [503, 400].each do |status|
    it "raises HTTPError, not OAuthError, for a #{status}" do
      client = client_credentials_client(RawHTTPServer.corrupt_gzip(status))

      expect { client.request_token }
        .to raise_error(Keycardai::OAuth::HTTPError, "token endpoint returned HTTP #{status}") { |e|
          expect(e).to be_an_instance_of(Keycardai::OAuth::HTTPError)
          expect(e.status).to eq(status)
        }
    end
  end

  describe ".parse_response scope" do
    [
      { name: "a space-separated string", scope: "read write", expected: %w[read write] },
      { name: "absent", scope: nil, expected: nil }
    ].each do |example|
      it "parses a scope that is #{example[:name]}" do
        payload = { "access_token" => "at", "scope" => example[:scope] }.compact

        expect(described_class.parse_response(json_response(payload)).scope).to eq(example[:expected])
      end
    end

    [5, %w[read write], { "read" => true }].each do |scope|
      it "raises ProtocolError invalid_response for a scope of #{scope.inspect}" do
        response = json_response({ "access_token" => "at", "scope" => scope })

        expect { described_class.parse_response(response) }
          .to raise_error(Keycardai::OAuth::ProtocolError, "token response scope is not a string") { |e|
            expect(e.code).to eq("invalid_response")
          }
      end
    end
  end
end
